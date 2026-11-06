"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const OUTPUT_DIR = path.join(ROOT, "output");
const RUN_DIR = path.join(OUTPUT_DIR, "real-run");
const EVIDENCE_DIR = path.join(RUN_DIR, "evidence");
const POLICY = JSON.parse(
  fs.readFileSync(path.join(ROOT, "config", "policy.json"), "utf8"),
);
const REGISTRY = "https://registry.npmjs.org/";
const UNAUTHORIZED_REGISTRY = "https://packages.example.invalid/";
const NPM = process.env.NPM_BIN || "npm";
const TRIVY = process.env.TRIVY_BIN || "trivy";

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function relativeToRoot(filePath) {
  return path.relative(ROOT, filePath).split(path.sep).join("/");
}

function evidencePath(id, fileName) {
  return relativeToRoot(path.join(EVIDENCE_DIR, id, fileName));
}

function runCommand(command, args, cwd, timeout = 900_000) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    timeout,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  });
  return {
    command: [command, ...args].join(" "),
    cwd,
    exitCode: result.status,
    signal: result.signal || null,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error ? result.error.message : null,
  };
}

function requireCommand(command, args, label) {
  const result = runCommand(command, args, ROOT, 30_000);
  if (result.error || result.exitCode !== 0) {
    throw new Error(
      `${label} no está disponible (${result.error || result.stderr || result.exitCode}).`,
    );
  }
  return result.stdout.trim();
}

function createProject(id, dependencies, { scripts, dependencySources } = {}) {
  const projectDir = path.join(RUN_DIR, "projects", id);
  fs.mkdirSync(projectDir, { recursive: true });
  const manifest = {
    name: `poc-lab-${id.toLowerCase()}`,
    version: "1.0.0",
    private: true,
    dependencies,
    ...(scripts ? { scripts } : {}),
  };

  if (dependencySources) {
    for (const [relativePath, packageManifest] of Object.entries(dependencySources)) {
      writeJson(path.join(projectDir, relativePath, "package.json"), packageManifest);
    }
  }

  writeJson(path.join(projectDir, "package.json"), manifest);
  const lockResult = runCommand(
    NPM,
    ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
    projectDir,
  );
  if (lockResult.exitCode !== 0) {
    writeJson(path.join(EVIDENCE_DIR, id, "lock-generation.json"), lockResult);
    throw new Error(
      `No se pudo generar el lockfile de ${id}: ${lockResult.stderr || lockResult.error}`,
    );
  }

  return projectDir;
}

function installWithoutScripts(id, projectDir) {
  const result = runCommand(
    NPM,
    ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    projectDir,
  );
  writeJson(path.join(EVIDENCE_DIR, id, "npm-ci.json"), {
    ...result,
    scriptsDisabled: true,
  });
  return result;
}

function classifyNpmCiResult(result) {
  if (result.exitCode === 0) {
    return "success";
  }
  const output = `${result.stdout}\n${result.stderr}`;
  if (
    /package\.json and package-lock\.json|package\.json and npm-shrinkwrap\.json/i.test(
      output,
    )
  ) {
    return "lockfile_inconsistent";
  }
  if (/ENETWORK|ECONN|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|network/i.test(output)) {
    return "network_error";
  }
  return "execution_error";
}

function urlHost(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:") {
      return null;
    }
    return parsed.host.toLowerCase();
  } catch {
    return null;
  }
}

function safeUrl(value) {
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return value;
  }
}

function isApprovedRegistry(value, policy = POLICY) {
  const candidate = urlHost(value);
  if (!candidate) {
    return false;
  }
  return policy.approvedRegistries.some((registry) => urlHost(registry) === candidate);
}

function lockfileHosts(projectDir) {
  const lockPath = path.join(projectDir, "package-lock.json");
  if (!fs.existsSync(lockPath)) {
    return [];
  }
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  return Object.values(lock.packages || {})
    .map((entry) => entry.resolved)
    .filter(Boolean);
}

function inspectRegistry(projectDir) {
  const configResult = runCommand(NPM, ["config", "get", "registry"], projectDir, 30_000);
  const effectiveRegistry = configResult.stdout.trim();
  const resolvedUrls = lockfileHosts(projectDir);
  return {
    effectiveRegistry: safeUrl(effectiveRegistry),
    configReadExitCode: configResult.exitCode,
    approved: isApprovedRegistry(effectiveRegistry),
    resolvedUrls,
    unauthorizedResolvedUrls: resolvedUrls.filter((url) => !isApprovedRegistry(url)),
    approvedResolvedUrls: resolvedUrls.filter((url) => isApprovedRegistry(url)),
  };
}

function inspectInstalledLifecycleScripts(projectDir) {
  const lock = JSON.parse(
    fs.readFileSync(path.join(projectDir, "package-lock.json"), "utf8"),
  );
  const detected = [];
  for (const location of Object.keys(lock.packages || {})) {
    if (!location.startsWith("node_modules/")) {
      continue;
    }
    const manifestPath = path.join(projectDir, location, "package.json");
    if (!fs.existsSync(manifestPath)) {
      continue;
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    for (const [name, body] of Object.entries(manifest.scripts || {})) {
      if (/^(preinstall|install|postinstall|prepare)$/i.test(name)) {
        detected.push({ package: manifest.name, script: name, body });
      }
    }
  }
  return detected;
}

function rewriteLockfileRegistry(projectDir) {
  const lockPath = path.join(projectDir, "package-lock.json");
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  for (const entry of Object.values(lock.packages || {})) {
    if (entry.resolved) {
      entry.resolved = entry.resolved.replace(
        "https://registry.npmjs.org/",
        UNAUTHORIZED_REGISTRY,
      );
    }
  }
  writeJson(lockPath, lock);
}

function npmVersion() {
  const result = runCommand(NPM, ["--version"], ROOT, 30_000);
  if (result.exitCode !== 0) {
    throw new Error(`No se pudo consultar npm: ${result.stderr || result.error}`);
  }
  return result.stdout.trim();
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function collectFiles(directory) {
  if (!fs.existsSync(directory)) {
    return [];
  }
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    return entry.isDirectory() ? collectFiles(fullPath) : [fullPath];
  });
}

function writeRunEvidenceManifest() {
  const files = [
    ...collectFiles(path.join(RUN_DIR, "projects")),
    ...collectFiles(path.join(RUN_DIR, "artifacts")),
    ...collectFiles(EVIDENCE_DIR).filter(
      (filePath) => path.basename(filePath) !== "evidence-manifest.json",
    ),
    path.join(RUN_DIR, "results.json"),
    path.join(RUN_DIR, "summary.csv"),
  ].filter((filePath) => fs.existsSync(filePath));
  const entries = files
    .sort()
    .map((filePath) => {
      const content = fs.readFileSync(filePath);
      return {
        path: relativeToRoot(filePath),
        sizeBytes: content.length,
        sha256: sha256(content),
      };
    });
  writeJson(path.join(EVIDENCE_DIR, "evidence-manifest.json"), {
    algorithm: "SHA-256",
    generatedAt: new Date().toISOString(),
    files: entries,
  });
}

function sha512Integrity(buffer) {
  return `sha512-${crypto.createHash("sha512").update(buffer).digest("base64")}`;
}

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} al consultar ${url}`);
  }
  return response.json();
}

async function prepareCleanPackage(observedAt) {
  const name = "chalk";
  const source = `https://registry.npmjs.org/${name}`;
  const metadata = await fetchJson(source);
  const version = metadata["dist-tags"]?.latest;
  const packageMetadata = metadata.versions?.[version];
  const releaseAt = metadata.time?.[version];
  if (!version || !packageMetadata || !releaseAt) {
    throw new Error(`La fuente ${source} no devolvió metadatos completos para S0`);
  }
  const ageDays = Math.floor(
    (Date.parse(observedAt) - Date.parse(releaseAt)) / 86_400_000,
  );
  const result = {
    package: name,
    version,
    source,
    observedAt,
    publishedAt: releaseAt,
    ageDays,
    license: packageMetadata.license || null,
    publishedIntegrity: packageMetadata.dist?.integrity || null,
  };
  writeJson(path.join(EVIDENCE_DIR, "S0", "clean-package-source.json"), result);
  return result;
}

async function prepareArtifactIntegrityScenario() {
  const evidenceDir = path.join(EVIDENCE_DIR, "S5");
  const artifactDir = path.join(RUN_DIR, "artifacts");
  fs.mkdirSync(evidenceDir, { recursive: true });
  fs.mkdirSync(artifactDir, { recursive: true });

  const metadataUrl = "https://registry.npmjs.org/lodash/4.17.21";
  const metadata = await fetchJson(metadataUrl);
  const response = await fetch(metadata.dist.tarball, {
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} al descargar el artefacto de S5`);
  }
  const original = Buffer.from(await response.arrayBuffer());
  const publishedIntegrity = metadata.dist.integrity;
  const originalIntegrity = sha512Integrity(original);
  const altered = Buffer.from(original);
  altered[Math.floor(altered.length / 2)] ^= 0x01;

  const originalPath = path.join(artifactDir, "lodash-4.17.21.tgz");
  const alteredPath = path.join(artifactDir, "lodash-4.17.21-alterado.tgz");
  fs.writeFileSync(originalPath, original);
  fs.writeFileSync(alteredPath, altered);

  const reference = {
    source: metadataUrl,
    tarball: metadata.dist.tarball,
    package: `${metadata.name}@${metadata.version}`,
    algorithm: "SHA-512 (SRI)",
    trustedIntegrity: publishedIntegrity,
    observedIntegrity: originalIntegrity,
    originalSha256: sha256(original),
    alteredSha256: sha256(altered),
    originalMatchesTrustedReference: originalIntegrity === publishedIntegrity,
    alteredMatchesTrustedReference: sha512Integrity(altered) === publishedIntegrity,
  };
  writeJson(path.join(evidenceDir, "trusted-reference.json"), reference);

  return {
    ...reference,
    originalPath,
    alteredPath,
    originalPasses: reference.originalMatchesTrustedReference,
    alteredPasses: reference.alteredMatchesTrustedReference,
  };
}

async function prepareMaintenanceScenario(observedAt) {
  const packageName = "request";
  const source = `https://registry.npmjs.org/${packageName}`;
  const metadata = await fetchJson(source);
  const versions = Object.keys(metadata.time || {})
    .filter((version) => version !== "created" && version !== "modified")
    .filter((version) => metadata.time[version]);
  const lastRelease = versions
    .map((version) => ({ version, date: metadata.time[version] }))
    .sort((left, right) => Date.parse(right.date) - Date.parse(left.date))[0];
  if (!lastRelease) {
    throw new Error(`La fuente ${source} no devolvió fechas de releases`);
  }
  const ageDays = Math.floor(
    (Date.parse(observedAt) - Date.parse(lastRelease.date)) / 86_400_000,
  );
  const result = {
    package: packageName,
    source,
    observedAt,
    latestTaggedVersion: metadata["dist-tags"]?.latest || null,
    lastReleaseVersion: lastRelease.version,
    lastReleaseAt: lastRelease.date,
    ageDays,
    signalOnly: true,
    decision: ageDays > POLICY.maximumMaintenanceAgeDays ? "revision_manual" : "permitir",
  };
  writeJson(path.join(EVIDENCE_DIR, "S6", "maintenance-source.json"), result);
  return result;
}

function scanWithTrivy(id, target, scanners = "vuln,license") {
  const reportPath = path.join(EVIDENCE_DIR, id, "trivy-report.json");
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  const run = runCommand(
    TRIVY,
    [
      "fs",
      "--scanners",
      scanners,
      "--format",
      "json",
      "--output",
      reportPath,
      "--quiet",
      "--skip-version-check",
      target,
    ],
    ROOT,
    1_200_000,
  );
  const evidence = {
    command: run.command,
    exitCode: run.exitCode,
    stdout: run.stdout,
    stderr: run.stderr,
    error: run.error,
    report: fs.existsSync(reportPath) ? relativeToRoot(reportPath) : null,
  };
  writeJson(path.join(EVIDENCE_DIR, id, "trivy-execution.json"), evidence);
  if (run.exitCode !== 0 || run.error) {
    throw new Error(
      `Trivy falló en ${id} (${run.exitCode}): ${run.stderr || run.error || "sin detalle"}`,
    );
  }
  if (!fs.existsSync(reportPath)) {
    throw new Error(`Trivy no generó el reporte de ${id}`);
  }
  return {
    reportPath,
    report: JSON.parse(fs.readFileSync(reportPath, "utf8")),
    execution: evidence,
  };
}

function trivyFindings(report, policy = POLICY) {
  const vulnerabilities = [];
  const packages = [];
  const licenses = [];
  for (const result of report?.Results || []) {
    for (const vulnerability of result.Vulnerabilities || []) {
      const cvssEntries = Object.values(vulnerability.CVSS || {});
      const scores = ["V3Score", "V40Score", "V4Score", "V2Score"]
        .map((key) =>
          cvssEntries
            .map((entry) => entry[key])
            .filter((score) => Number.isFinite(score))
            .map(Number),
        )
        .find((candidateScores) => candidateScores.length > 0) || [];
      const cvss = scores.length ? Math.max(...scores) : null;
      const scannerSeverity = String(vulnerability.Severity || "UNKNOWN").toUpperCase();
      const blocking =
        scannerSeverity === "CRITICAL" ||
        (cvss !== null && cvss >= policy.blockCvssAtOrAbove);
      const review =
        scannerSeverity === "HIGH" ||
        (cvss !== null && cvss >= policy.reviewCvssAtOrAbove);
      const references = Array.isArray(vulnerability.References)
        ? vulnerability.References
        : [];
      vulnerabilities.push({
        id: vulnerability.VulnerabilityID,
        package: vulnerability.PkgName,
        version: vulnerability.InstalledVersion,
        severity: scannerSeverity,
        cvss,
        controlSeverity: blocking ? "bloqueante" : review ? "advertencia" : "informativo",
        source: {
          dataSource: vulnerability.DataSource
            ? {
                id: vulnerability.DataSource.ID || null,
                name: vulnerability.DataSource.Name || null,
                url: vulnerability.DataSource.URL || null,
              }
            : null,
          severitySource: vulnerability.SeveritySource || null,
          primaryUrl: vulnerability.PrimaryURL || null,
          nvdUrl:
            references.find((reference) =>
              /^https:\/\/nvd\.nist\.gov\/vuln\/detail\//i.test(reference),
            ) || null,
          cveRecordUrl:
            references.find((reference) =>
              /^https:\/\/www\.cve\.org\/CVERecord\?id=/i.test(reference),
            ) || null,
          advisoryUrl:
            references.find((reference) =>
              /^https:\/\/github\.com\/advisories\/GHSA-/i.test(reference),
            ) || null,
        },
        fixedVersion: vulnerability.FixedVersion || null,
      });
    }

    for (const packageInfo of result.Packages || []) {
      packages.push(packageInfo);
      for (const license of packageInfo.Licenses || []) {
        licenses.push({ package: packageInfo.Name, version: packageInfo.Version, name: license });
      }
    }
    for (const license of result.Licenses || []) {
      licenses.push({
        package: license.PkgName,
        name: license.Name,
        scannerSeverity: license.Severity,
        category: license.Category,
        confidence: license.Confidence,
      });
    }
  }

  const uniqueLicenses = Array.from(
    new Map(
      licenses.map((license) => [
        `${license.package || ""}:${license.name || ""}`,
        license,
      ]),
    ).values(),
  );
  return { vulnerabilities, licenses: uniqueLicenses, packages };
}

function decisionForFindings(findings) {
  if (findings.some((finding) => finding.severity === "bloqueante")) {
    return "bloquear";
  }
  if (findings.some((finding) => finding.severity === "advertencia")) {
    return "revision_manual";
  }
  return "permitir";
}

function addScannerFindings(findings, scan) {
  const parsed = trivyFindings(scan.report);
  for (const vulnerability of parsed.vulnerabilities) {
    if (vulnerability.controlSeverity !== "informativo") {
      findings.push({
        control: "vulnerabilidades",
        severity: vulnerability.controlSeverity,
        reference: vulnerability.id,
        package: vulnerability.package,
        version: vulnerability.version,
        cvss: vulnerability.cvss,
        source: vulnerability.source,
        message: `Trivy detectó ${vulnerability.severity}${vulnerability.cvss === null ? "" : ` (CVSS ${vulnerability.cvss})`}.`,
      });
    }
  }
  for (const license of parsed.licenses) {
    if (license.name && !POLICY.allowedLicenses.includes(license.name)) {
      findings.push({
        control: "licencia",
        severity: "bloqueante",
        reference: license.name,
        package: license.package,
        message: `Licencia fuera de la política: ${license.name}`,
      });
    }
  }
  return parsed;
}

function scenarioResult(id, name, expectedDecision, findings, evidence, extras = {}) {
  const decision = decisionForFindings(findings);
  return {
    id,
    name,
    expectedDecision,
    decision,
    passed: decision === expectedDecision && !extras.executionError,
    findings,
    evidence,
    ...extras,
  };
}

function writeCsv(results) {
  const escape = (value) => `"${String(value).replaceAll('"', '""')}"`;
  const headings = ["escenario", "nombre", "esperado", "obtenido", "estado", "hallazgos", "evidencias"];
  const rows = results.map((result) => [
    result.id,
    result.name,
    result.expectedDecision,
    result.decision,
    result.passed ? "PASS" : "FAIL",
    result.findings.map((finding) => finding.reference || finding.control).join("; "),
    (result.evidence || []).join("; "),
  ]);
  fs.writeFileSync(
    path.join(RUN_DIR, "summary.csv"),
    `${[headings, ...rows].map((row) => row.map(escape).join(",")).join("\n")}\n`,
    "utf8",
  );
}

function formatConsoleReport(results, metadata, scans) {
  console.log("\nCorrida de Trivy — datos originales del escáner\n");
  const database = metadata?.trivyDatabase?.VulnerabilityDB;
  console.log(
    `Trivy ${metadata?.trivyVersion || "desconocido"}; base de vulnerabilidades v${database?.Version ?? "desconocida"}; ` +
      `descargada ${database?.DownloadedAt || "sin dato"}; actualizada ${database?.UpdatedAt || "sin dato"}.`,
  );

  const executions = Object.entries(scans).map(([id, scan]) => ({
    escenario: id,
    codigo: scan.execution.exitCode,
    comando: scan.execution.command,
    reporte: scan.execution.report,
  }));
  if (executions.length > 0) {
    console.log("\nComandos ejecutados y reportes generados:");
    console.table(executions);
  }

  const vulnerabilityRows = Object.entries(scans).flatMap(([id, scan]) =>
    trivyFindings(scan.report).vulnerabilities.map((vulnerability) => ({
      escenario: id,
      hallazgo: vulnerability.id,
      paquete: `${vulnerability.package}@${vulnerability.version}`,
      severidad_Trivy: vulnerability.severity,
      CVSS: vulnerability.cvss ?? "sin dato",
      fuente: vulnerability.source.dataSource?.name || "No informada",
      origen: vulnerability.source.dataSource?.url || "No informado",
      URL_Trivy: vulnerability.source.primaryUrl || "No informada",
      NVD: vulnerability.source.nvdUrl || "No informado",
      GHSA: vulnerability.source.advisoryUrl || "No informado",
    })),
  );
  console.log("\nHallazgos y procedencia según los reportes de Trivy:");
  if (vulnerabilityRows.length > 0) {
    console.table(vulnerabilityRows);
  } else {
    console.log("Trivy no reportó vulnerabilidades con fuentes para mostrar.");
  }
  console.log(
    `Comando y estado: ${path.join(RUN_DIR, "evidence/<escenario>/trivy-execution.json")}`,
  );
  console.log(
    `Reporte JSON original y referencias completas: ${path.join(RUN_DIR, "evidence/<escenario>/trivy-report.json")}`,
  );

  console.log("\nEvaluación de la PoC sobre esos resultados\n");
  console.table(
    results.map((result) => ({
      escenario: result.id,
      esperado: result.expectedDecision,
      obtenido: result.decision,
      estado: result.passed ? "PASS" : "FAIL",
      hallazgos: result.findings.length,
    })),
  );
  console.log(`Informe: ${path.join(RUN_DIR, "results.json")}`);
  console.log(`Resumen: ${path.join(RUN_DIR, "summary.csv")}`);
}

async function runRealScenarios() {
  const trivyVersionOutput = requireCommand(TRIVY, ["--version"], "Trivy");
  const trivyVersion = trivyVersionOutput.match(/Version:\s*(.+)/)?.[1] || trivyVersionOutput;
  const nodeVersion = process.version;
  const currentNpmVersion = npmVersion();
  const observedAt = new Date().toISOString();

  fs.rmSync(RUN_DIR, { recursive: true, force: true });
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  fs.writeFileSync(
    path.join(RUN_DIR, "README.txt"),
    "Ejecución generada por la PoC. Los proyectos de laboratorio usan dependencias fijadas; los scripts de lifecycle se instalan con --ignore-scripts.\n",
    "utf8",
  );

  const scenarios = {};
  const findings = {};
  const scans = {};
  const installResults = {};

  const cleanPackage = await prepareCleanPackage(observedAt);
  scenarios.S0 = createProject("S0", { [cleanPackage.package]: cleanPackage.version });
  installResults.S0 = installWithoutScripts("S0", scenarios.S0);
  const cleanLock = JSON.parse(
    fs.readFileSync(path.join(scenarios.S0, "package-lock.json"), "utf8"),
  );
  const cleanLockEntry = cleanLock.packages[`node_modules/${cleanPackage.package}`];
  const cleanLifecycleScripts = inspectInstalledLifecycleScripts(scenarios.S0);
  const cleanControls = {
    package: `${cleanPackage.package}@${cleanPackage.version}`,
    npmCi: classifyNpmCiResult(installResults.S0),
    lockIntegrity: cleanLockEntry?.integrity || null,
    packageIntegrityVerifiedByNpmCi:
      classifyNpmCiResult(installResults.S0) === "success" && Boolean(cleanLockEntry?.integrity),
    license: cleanPackage.license,
    licenseAllowed: POLICY.allowedLicenses.includes(cleanPackage.license),
    releaseAgeDays: cleanPackage.ageDays,
    withinMaintenancePolicy: cleanPackage.ageDays <= POLICY.maximumMaintenanceAgeDays,
    lifecycleScripts: cleanLifecycleScripts,
  };
  writeJson(path.join(EVIDENCE_DIR, "S0", "baseline-controls.json"), cleanControls);

  const s1Dir = path.join(RUN_DIR, "projects", "S1");
  fs.mkdirSync(s1Dir, { recursive: true });
  fs.writeFileSync(
    path.join(s1Dir, "pom.xml"),
    [
      '<project xmlns="http://maven.apache.org/POM/4.0.0">',
      "  <modelVersion>4.0.0</modelVersion>",
      "  <groupId>lab.poc</groupId>",
      "  <artifactId>log4j-vulnerability-fixture</artifactId>",
      "  <version>1.0.0</version>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>org.apache.logging.log4j</groupId>",
      "      <artifactId>log4j-core</artifactId>",
      "      <version>2.14.1</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n"),
    "utf8",
  );

  scenarios.S2 = createProject("S2", { [cleanPackage.package]: cleanPackage.version });
  fs.writeFileSync(path.join(scenarios.S2, ".npmrc"), `registry=${UNAUTHORIZED_REGISTRY}\n`, "utf8");
  rewriteLockfileRegistry(scenarios.S2);

  scenarios.S3 = createProject("S3", { [cleanPackage.package]: cleanPackage.version });
  const s3ManifestPath = path.join(scenarios.S3, "package.json");
  const s3Manifest = JSON.parse(fs.readFileSync(s3ManifestPath, "utf8"));
  s3Manifest.dependencies[cleanPackage.package] = cleanPackage.version.startsWith("6.")
    ? "5.6.2"
    : "6.0.1";
  writeJson(s3ManifestPath, s3Manifest);
  installResults.S3 = runCommand(
    NPM,
    ["ci", "--ignore-scripts", "--no-audit"],
    scenarios.S3,
  );
  writeJson(path.join(EVIDENCE_DIR, "S3", "npm-ci.json"), installResults.S3);
  installResults.S3.classification = classifyNpmCiResult(installResults.S3);

  const localScriptManifest = {
    name: "lab-postinstall-fixture",
    version: "1.0.0",
    private: true,
    license: "MIT",
    scripts: {
      postinstall:
        "node -e \"require('fs').writeFileSync('postinstall-marker.txt','executed')\"",
    },
  };
  scenarios.S4 = createProject(
    "S4",
    { "lab-postinstall-fixture": "file:./fixtures/lab-postinstall-fixture" },
    { dependencySources: { "fixtures/lab-postinstall-fixture": localScriptManifest } },
  );
  installResults.S4 = installWithoutScripts("S4", scenarios.S4);
  const installedScriptPackage = path.join(
    scenarios.S4,
    "node_modules",
    "lab-postinstall-fixture",
  );
  const installedScriptManifest = JSON.parse(
    fs.readFileSync(path.join(installedScriptPackage, "package.json"), "utf8"),
  );
  const lifecycleScripts = Object.keys(installedScriptManifest.scripts || {}).filter((name) =>
    /^(preinstall|install|postinstall|prepare)$/i.test(name),
  );
  const markerPath = path.join(installedScriptPackage, "postinstall-marker.txt");
  const scriptEvidence = {
    package: "lab-postinstall-fixture@1.0.0",
    lifecycleScripts,
    scriptBody: installedScriptManifest.scripts.postinstall,
    scriptsDisabledDuringInstall: true,
    markerExists: fs.existsSync(markerPath),
    detection: lifecycleScripts.length > 0,
  };
  writeJson(path.join(EVIDENCE_DIR, "S4", "script-inspection.json"), scriptEvidence);

  const artifact = await prepareArtifactIntegrityScenario();
  const maintenance = await prepareMaintenanceScenario(observedAt);

  scenarios.S7 = createProject("S7", {
    "@substrate/connect-known-chains": "1.10.3",
  });
  installResults.S7 = installWithoutScripts("S7", scenarios.S7);

  scenarios.S8 = createProject("S8", { "path-to-regexp": "0.1.7" });
  installResults.S8 = installWithoutScripts("S8", scenarios.S8);

  scenarios.S9 = createProject("S9", { lodash: "4.17.21" });
  installResults.S9 = installWithoutScripts("S9", scenarios.S9);
  fs.writeFileSync(path.join(scenarios.S9, ".npmrc"), `registry=${UNAUTHORIZED_REGISTRY}\n`, "utf8");
  rewriteLockfileRegistry(scenarios.S9);

  for (const id of ["S0", "S1", "S2", "S3", "S4", "S7", "S8", "S9"]) {
    scans[id] = scanWithTrivy(id, scenarios[id] || s1Dir);
  }

  const registryChecks = {};
  for (const id of ["S0", "S2", "S3", "S4", "S7", "S8", "S9"]) {
    registryChecks[id] = inspectRegistry(scenarios[id]);
    writeJson(path.join(EVIDENCE_DIR, id, "registry-inspection.json"), registryChecks[id]);
  }

  for (const id of Object.keys(scans)) {
    findings[id] = [];
    addScannerFindings(findings[id], scans[id]);
  }

  if (!registryChecks.S0.approved || registryChecks.S0.unauthorizedResolvedUrls.length) {
    findings.S0.push({ control: "origen", severity: "bloqueante", message: "S0 usa una fuente fuera de la política." });
  }
  if (classifyNpmCiResult(installResults.S0) !== "success") {
    findings.S0.push({ control: "reproducibilidad", severity: "bloqueante", message: "npm ci no pudo instalar el caso limpio." });
  }
  if (!cleanControls.packageIntegrityVerifiedByNpmCi) {
    findings.S0.push({ control: "integridad", severity: "bloqueante", message: "El lockfile limpio no aporta integridad verificable para el paquete." });
  }
  if (!cleanControls.licenseAllowed) {
    findings.S0.push({ control: "licencia", severity: "bloqueante", message: `Licencia de S0 fuera de política: ${cleanControls.license}.` });
  }
  if (cleanControls.lifecycleScripts.length > 0) {
    findings.S0.push({ control: "ejecucion", severity: "bloqueante", message: "S0 contiene scripts de ciclo de vida no permitidos." });
  }
  if (!cleanControls.withinMaintenancePolicy) {
    findings.S0.push({ control: "mantenimiento", severity: "advertencia", message: "El release del paquete limpio supera la antigüedad permitida." });
  }

  findings.S1 = findings.S1 || [];
  if (!findings.S1.some((finding) => finding.control === "vulnerabilidades" && finding.severity === "bloqueante")) {
    findings.S1.push({ control: "vulnerabilidades", severity: "advertencia", message: "Trivy no confirmó un hallazgo crítico para S1." });
  }

  findings.S2 = findings.S2 || [];
  if (registryChecks.S2.approved && registryChecks.S2.unauthorizedResolvedUrls.length === 0) {
    findings.S2.push({ control: "origen", severity: "advertencia", message: "No se detectó el registro no autorizado de S2." });
  } else {
    findings.S2.push({
      control: "origen",
      severity: "bloqueante",
      message: "Registro efectivo o URL de resolución fuera de la lista permitida.",
    });
  }

  findings.S3 = findings.S3 || [];
  if (installResults.S3.classification === "lockfile_inconsistent") {
    findings.S3.push({ control: "reproducibilidad", severity: "bloqueante", message: "npm ci rechazó la inconsistencia entre manifiesto y lockfile." });
  } else {
    findings.S3.push({
      control: "reproducibilidad",
      severity: "advertencia",
      message: `Resultado inesperado de npm ci: ${installResults.S3.classification}.`,
    });
  }

  findings.S4 = findings.S4 || [];
  if (scriptEvidence.detection) {
    findings.S4.push({ control: "ejecucion", severity: "bloqueante", message: "Se detectó un postinstall; el ensayo lo instaló sin ejecutar scripts." });
  }
  if (scriptEvidence.markerExists) {
    findings.S4.push({ control: "seguridad-del-ensayo", severity: "bloqueante", message: "El marcador demuestra que el postinstall se ejecutó." });
  }

  findings.S5 = [];
  if (!artifact.originalPasses) {
    findings.S5.push({ control: "integridad", severity: "advertencia", message: "El artefacto original no coincide con la integridad publicada por npm." });
  }
  if (artifact.alteredPasses) {
    findings.S5.push({ control: "integridad", severity: "advertencia", message: "El artefacto alterado superó incorrectamente el control." });
  } else {
    findings.S5.push({ control: "integridad", severity: "bloqueante", message: "La integridad detectó la modificación del artefacto." });
  }

  findings.S6 = [];
  if (maintenance.ageDays > POLICY.maximumMaintenanceAgeDays) {
    findings.S6.push({
      control: "mantenimiento",
      severity: "advertencia",
      message: `Último release hace ${maintenance.ageDays} días; señal para revisión manual, no prueba de abandono.`,
    });
  }

  findings.S7 = findings.S7 || [];
  if (!findings.S7.some((finding) => finding.control === "licencia" && finding.severity === "bloqueante")) {
    findings.S7.push({ control: "licencia", severity: "advertencia", message: "Trivy no identificó una licencia fuera de política para S7." });
  }

  findings.S8 = findings.S8 || [];
  const s8BlockingVulnerability = findings.S8.some(
    (finding) => finding.control === "vulnerabilidades" && finding.severity === "bloqueante",
  );
  if (s8BlockingVulnerability) {
    findings.S8.push({ control: "escenario", severity: "advertencia", message: "La base actual contiene un hallazgo bloqueante; S8 deja de aislar solo severidad alta." });
  }
  if (!findings.S8.some((finding) => finding.control === "vulnerabilidades" && finding.severity === "advertencia")) {
    findings.S8.push({ control: "vulnerabilidades", severity: "advertencia", message: "No se detectó vulnerabilidad alta para S8." });
  }

  findings.S9 = findings.S9 || [];
  if (!registryChecks.S9.approved || registryChecks.S9.unauthorizedResolvedUrls.length) {
    findings.S9.push({ control: "origen", severity: "bloqueante", message: "Fuente no autorizada detectada en el lockfile/configuración de S9." });
  }
  if (!artifact.alteredPasses) {
    findings.S9.push({ control: "integridad", severity: "bloqueante", message: "El artefacto alterado asociado a S9 no coincide con la referencia confiable." });
  }
  if (!findings.S9.some((finding) => finding.severity === "bloqueante")) {
    findings.S9.push({ control: "escenario", severity: "advertencia", message: "S9 no produjo hallazgos bloqueantes; revisar fixture y base del escáner." });
  }

  const scenariosResults = [
    scenarioResult("S0", "Caso limpio", "permitir", findings.S0, [evidencePath("S0", "trivy-report.json"), evidencePath("S0", "trivy-execution.json"), evidencePath("S0", "registry-inspection.json"), evidencePath("S0", "clean-package-source.json"), evidencePath("S0", "baseline-controls.json")], { npmCi: classifyNpmCiResult(installResults.S0), trivyExecution: scans.S0.execution }),
    scenarioResult("S1", "Vulnerabilidad crítica", "bloquear", findings.S1, [evidencePath("S1", "trivy-report.json"), evidencePath("S1", "trivy-execution.json")], { trivyExecution: scans.S1.execution }),
    scenarioResult("S2", "Registro no autorizado", "bloquear", findings.S2, [evidencePath("S2", "registry-inspection.json"), evidencePath("S2", "trivy-report.json"), evidencePath("S2", "trivy-execution.json")], { dependencyDownloadAttempted: false, trivyExecution: scans.S2.execution }),
    scenarioResult("S3", "Lockfile inconsistente", "bloquear", findings.S3, [evidencePath("S3", "npm-ci.json"), evidencePath("S3", "trivy-report.json"), evidencePath("S3", "trivy-execution.json")], { npmCi: installResults.S3.classification, trivyExecution: scans.S3.execution }),
    scenarioResult("S4", "Script no autorizado", "bloquear", findings.S4, [evidencePath("S4", "script-inspection.json"), evidencePath("S4", "trivy-report.json"), evidencePath("S4", "trivy-execution.json")], { markerCreated: scriptEvidence.markerExists, scriptsExecuted: false, trivyExecution: scans.S4.execution }),
    scenarioResult("S5", "Artefacto alterado", "bloquear", findings.S5, [evidencePath("S5", "trusted-reference.json"), relativeToRoot(artifact.originalPath), relativeToRoot(artifact.alteredPath)], { originalIntegrityPassed: artifact.originalPasses, alteredIntegrityPassed: artifact.alteredPasses }),
    scenarioResult("S6", "Falta de mantenimiento", "revision_manual", findings.S6, [evidencePath("S6", "maintenance-source.json")], { maintenanceAgeDays: maintenance.ageDays }),
    scenarioResult("S7", "Licencia no permitida", "bloquear", findings.S7, [evidencePath("S7", "trivy-report.json"), evidencePath("S7", "trivy-execution.json")], { trivyExecution: scans.S7.execution }),
    scenarioResult("S8", "Vulnerabilidad alta", "revision_manual", findings.S8, [evidencePath("S8", "trivy-report.json"), evidencePath("S8", "trivy-execution.json")], { trivyExecution: scans.S8.execution }),
    scenarioResult("S9", "Condiciones combinadas", "bloquear", findings.S9, [evidencePath("S9", "trivy-report.json"), evidencePath("S9", "trivy-execution.json"), evidencePath("S9", "registry-inspection.json"), evidencePath("S5", "trusted-reference.json"), relativeToRoot(artifact.alteredPath)], { trivyExecution: scans.S9.execution }),
  ];

  const dbVersionResult = runCommand(TRIVY, ["version", "--format", "json"], ROOT, 30_000);
  let trivyDatabase = null;
  if (dbVersionResult.exitCode === 0) {
    try {
      trivyDatabase = JSON.parse(dbVersionResult.stdout);
    } catch {
      trivyDatabase = { raw: dbVersionResult.stdout.trim() };
    }
  }
  const results = {
    metadata: {
      name: "PoC gestión segura de dependencias — ensayo real",
      executionMode: "real-tool-and-lab-fixtures",
      observedAt,
      nodeVersion,
      npmVersion: currentNpmVersion,
      trivyVersion,
      trivyDatabase,
      policyId: POLICY.policyId,
      policyVersion: POLICY.policyVersion,
      policySha256: crypto.createHash("sha256").update(JSON.stringify(POLICY)).digest("hex"),
      networkSources: ["registry.npmjs.org", "Trivy vulnerability database"],
      safety: "Todos los npm ci usan --ignore-scripts; S4 comprueba que postinstall no se ejecuta.",
      note: "Los informes Trivy son salidas originales; npm audit no sustituye el escáner.",
    },
    policy: POLICY,
    scenarios: scenariosResults,
  };
  writeJson(path.join(RUN_DIR, "results.json"), results);
  writeCsv(scenariosResults);

  for (const projectDir of Object.values(scenarios)) {
    fs.rmSync(path.join(projectDir, "node_modules"), { recursive: true, force: true });
  }
  writeRunEvidenceManifest();
  formatConsoleReport(scenariosResults, results.metadata, scans);

  const failed = scenariosResults.filter((scenario) => !scenario.passed);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
  return results;
}

module.exports = {
  classifyNpmCiResult,
  decisionForFindings,
  isApprovedRegistry,
  trivyFindings,
  runRealScenarios,
};
