"use strict";

const crypto = require("crypto");

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] = canonicalize(value[key]);
        return result;
      }, {});
  }
  return value;
}

function sha256(value) {
  const input =
    typeof value === "string"
      ? value
      : JSON.stringify(canonicalize(value));
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function addFinding(findings, condition, finding) {
  if (condition) {
    findings.push(finding);
  }
}

function evaluateBaseline(scenario) {
  const findings = [];
  addFinding(findings, !scenario.manifestValid, {
    control: "sintaxis_manifiesto",
    severity: "bloqueante",
    message: "El manifiesto no puede procesarse.",
  });
  return {
    decision: findings.length > 0 ? "bloquear" : "permitir",
    findings,
    evidence: ["manifest-parse-report"],
  };
}

function evaluateVulnerabilities(vulnerabilities, policy, findings) {
  for (const vulnerability of vulnerabilities) {
    const descriptor = `${vulnerability.id} (${vulnerability.source}, CVSS ${vulnerability.cvss})`;
    if (policy.blockKnownExploited && vulnerability.knownExploited) {
      findings.push({
        control: "vulnerabilidades",
        severity: "bloqueante",
        reference: vulnerability.id,
        message: `${descriptor}: vulnerabilidad marcada como explotada.`,
      });
    } else if (vulnerability.cvss >= policy.blockCvssAtOrAbove) {
      findings.push({
        control: "vulnerabilidades",
        severity: "bloqueante",
        reference: vulnerability.id,
        message: `${descriptor}: supera el umbral de bloqueo.`,
      });
    } else if (vulnerability.cvss >= policy.reviewCvssAtOrAbove) {
      findings.push({
        control: "vulnerabilidades",
        severity: "advertencia",
        reference: vulnerability.id,
        message: `${descriptor}: requiere análisis de riesgo manual.`,
      });
    }
  }
}

function buildSbom(scenario, policy) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:poc-${scenario.id.toLowerCase()}`,
    version: 1,
    metadata: {
      timestamp: policy.observationDate,
      component: {
        type: "application",
        name: "dependency-governance-poc",
        version: "2.0.0",
      },
      properties: [
        { name: "poc:scenario", value: scenario.id },
        { name: "poc:data-mode", value: "controlled-snapshot" },
      ],
    },
    components: scenario.components,
    vulnerabilities: scenario.vulnerabilities.map((vulnerability) => ({
      id: vulnerability.id,
      source: { name: vulnerability.source },
      ratings: [
        {
          score: vulnerability.cvss,
          method: "CVSSv3",
        },
      ],
      properties: [
        {
          name: "poc:known-exploited",
          value: String(vulnerability.knownExploited),
        },
      ],
    })),
  };
}

function buildProvenance(scenario, policy, actualArtifactSha256) {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: `${scenario.id}-artifact`,
        digest: { sha256: actualArtifactSha256 },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://example.org/poc/dependency-validation/v2",
        externalParameters: {
          scenario: scenario.id,
          policyId: policy.policyId,
          policyVersion: policy.policyVersion,
        },
        resolvedDependencies: scenario.components.map((component) => ({
          uri: component.purl,
          digest: { sha256: sha256(component) },
        })),
      },
      runDetails: {
        builder: { id: "local-node-poc" },
        metadata: { invocationId: `poc-${scenario.id}` },
      },
    },
  };
}

function evaluateProposed(scenario, policy) {
  const findings = [];
  const vulnerabilities = scenario.vulnerabilities || [];
  const actualArtifactSha256 = sha256(scenario.actualArtifactContent);
  const trustedArtifactSha256 = sha256(scenario.trustedArtifactContent);

  addFinding(
    findings,
    !policy.approvedRegistries.includes(scenario.registry),
    {
      control: "origen",
      severity: "bloqueante",
      message: `Registro no autorizado: ${scenario.registry}`,
    },
  );
  addFinding(
    findings,
    policy.requireLockfile && !scenario.lockfilePresent,
    {
      control: "reproducibilidad",
      severity: "bloqueante",
      message: "No se encontró el archivo de bloqueo requerido.",
    },
  );
  addFinding(
    findings,
    scenario.lockfilePresent && !scenario.lockfileConsistent,
    {
      control: "reproducibilidad",
      severity: "bloqueante",
      message: "El manifiesto y el archivo de bloqueo no son consistentes.",
    },
  );
  evaluateVulnerabilities(vulnerabilities, policy, findings);
  addFinding(
    findings,
    !policy.allowLifecycleScripts && scenario.hasLifecycleScript,
    {
      control: "ejecucion",
      severity: "bloqueante",
      message: "La dependencia contiene un script de ciclo de vida no aprobado.",
    },
  );
  addFinding(
    findings,
    actualArtifactSha256 !== trustedArtifactSha256,
    {
      control: "integridad",
      severity: "bloqueante",
      message: "El SHA-256 calculado no coincide con el valor de confianza.",
      expectedSha256: trustedArtifactSha256,
      actualSha256: actualArtifactSha256,
    },
  );
  addFinding(
    findings,
    scenario.maintenanceAgeDays > policy.maximumMaintenanceAgeDays,
    {
      control: "mantenimiento",
      severity: "advertencia",
      message: `El componente lleva ${scenario.maintenanceAgeDays} días sin mantenimiento.`,
    },
  );
  addFinding(
    findings,
    !policy.allowedLicenses.includes(scenario.license),
    {
      control: "licencia",
      severity: "bloqueante",
      message: `Licencia no permitida: ${scenario.license}`,
    },
  );

  const hasBlocking = findings.some(
    (finding) => finding.severity === "bloqueante",
  );
  const hasWarning = findings.some(
    (finding) => finding.severity === "advertencia",
  );
  const decision = hasBlocking
    ? "bloquear"
    : hasWarning
      ? "revision_manual"
      : "permitir";

  const sbom = buildSbom(scenario, policy);
  const policyReport = {
    scenario: scenario.id,
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    decision,
    findings,
    checksExecuted: [
      "origen",
      "reproducibilidad",
      "vulnerabilidades",
      "ejecucion",
      "integridad",
      "mantenimiento",
      "licencia",
    ],
  };
  const provenance =
    decision === "bloquear"
      ? null
      : buildProvenance(scenario, policy, actualArtifactSha256);
  const manifest = {
    algorithm: "SHA-256",
    artifact: actualArtifactSha256,
    sbom: sha256(sbom),
    policyReport: sha256(policyReport),
    provenance: provenance ? sha256(provenance) : null,
  };

  return {
    decision,
    findings,
    checksExecuted: policyReport.checksExecuted,
    evidence: { sbom, policyReport, provenance, manifest },
  };
}

function hasCompleteEvidence(result) {
  const evidence = result.proposed.evidence;
  const baseComplete =
    evidence &&
    evidence.sbom &&
    evidence.policyReport &&
    evidence.manifest &&
    /^[a-f0-9]{64}$/.test(evidence.manifest.sbom) &&
    /^[a-f0-9]{64}$/.test(evidence.manifest.policyReport);
  if (!baseComplete) {
    return false;
  }
  if (result.proposed.decision !== "bloquear") {
    return (
      evidence.provenance &&
      /^[a-f0-9]{64}$/.test(evidence.manifest.provenance)
    );
  }
  return evidence.provenance === null;
}

function calculateMetrics(firstRun, allRuns) {
  const riskScenarios = firstRun.filter((result) => result.containsRisk);
  const cleanScenarios = firstRun.filter((result) => !result.containsRisk);
  const baselineDetected = riskScenarios.filter(
    (result) =>
      result.baseline.decision !== "permitir" ||
      result.baseline.findings.length > 0,
  );
  const proposedDetected = riskScenarios.filter(
    (result) =>
      result.proposed.decision !== "permitir" ||
      result.proposed.findings.length > 0,
  );
  const correct = firstRun.filter(
    (result) => result.proposed.decision === result.expectedDecision,
  );
  const falsePositives = cleanScenarios.filter(
    (result) =>
      result.proposed.decision !== "permitir" ||
      result.proposed.findings.length > 0,
  );
  const stable = firstRun.filter((reference) =>
    allRuns.every((run) => {
      const current = run.find((result) => result.id === reference.id);
      return (
        current &&
        current.proposed.decision === reference.proposed.decision &&
        sha256(current.proposed.findings) ===
          sha256(reference.proposed.findings) &&
        sha256(current.proposed.evidence) ===
          sha256(reference.proposed.evidence)
      );
    }),
  );
  const completeEvidence = firstRun.filter(hasCompleteEvidence);

  return {
    totalScenarios: firstRun.length,
    riskScenarios: riskScenarios.length,
    baselineDetectedRisks: baselineDetected.length,
    proposedDetectedRisks: proposedDetected.length,
    baselineRiskDetectionRate:
      riskScenarios.length === 0
        ? 0
        : baselineDetected.length / riskScenarios.length,
    proposedRiskDetectionRate:
      riskScenarios.length === 0
        ? 0
        : proposedDetected.length / riskScenarios.length,
    decisionAccuracy:
      firstRun.length === 0 ? 0 : correct.length / firstRun.length,
    cleanFalsePositiveRate:
      cleanScenarios.length === 0
        ? 0
        : falsePositives.length / cleanScenarios.length,
    reproducibilityRate:
      firstRun.length === 0 ? 0 : stable.length / firstRun.length,
    evidenceCompletenessRate:
      firstRun.length === 0 ? 0 : completeEvidence.length / firstRun.length,
    decisions: {
      bloquear: firstRun.filter(
        (result) => result.proposed.decision === "bloquear",
      ).length,
      revision_manual: firstRun.filter(
        (result) => result.proposed.decision === "revision_manual",
      ).length,
      permitir: firstRun.filter(
        (result) => result.proposed.decision === "permitir",
      ).length,
    },
  };
}

module.exports = {
  canonicalize,
  sha256,
  evaluateBaseline,
  evaluateProposed,
  calculateMetrics,
};
