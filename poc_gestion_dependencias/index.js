"use strict";

const fs = require("fs");
const path = require("path");
const {
  evaluateBaseline,
  evaluateProposed,
  calculateMetrics,
  sha256,
} = require("./src/policy-engine");

const ROOT = __dirname;
const OUTPUT_DIR = path.join(ROOT, "output");
const EVIDENCE_DIR = path.join(OUTPUT_DIR, "evidence");
const REPETITIONS = 5;
const quiet = process.argv.includes("--quiet");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function csvCell(value) {
  const text = String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

function writeSummaryCsv(results) {
  const headings = [
    "escenario",
    "nombre",
    "decision_esperada",
    "flujo_inicial",
    "flujo_propuesto",
    "cantidad_hallazgos",
    "controles_activados",
  ];
  const rows = results.map((result) => [
    result.id,
    result.name,
    result.expectedDecision,
    result.baseline.decision,
    result.proposed.decision,
    result.proposed.findings.length,
    result.proposed.findings.map((finding) => finding.control).join("; "),
  ]);
  const csv = [headings, ...rows]
    .map((row) => row.map(csvCell).join(","))
    .join("\n");
  fs.writeFileSync(path.join(OUTPUT_DIR, "summary.csv"), `${csv}\n`, "utf8");
}

function makeResult(scenario, policy, repetition) {
  return {
    id: scenario.id,
    name: scenario.name,
    repetition,
    containsRisk: scenario.containsRisk,
    expectedDecision: scenario.expectedDecision,
    baseline: evaluateBaseline(scenario),
    proposed: evaluateProposed(scenario, policy),
  };
}

function writeEvidence(results) {
  for (const result of results) {
    const scenarioDir = path.join(EVIDENCE_DIR, result.id);
    writeJson(path.join(scenarioDir, "sbom.cdx.json"), result.proposed.evidence.sbom);
    writeJson(
      path.join(scenarioDir, "policy-report.json"),
      result.proposed.evidence.policyReport,
    );
    writeJson(
      path.join(scenarioDir, "evidence-manifest.json"),
      result.proposed.evidence.manifest,
    );
    if (result.proposed.evidence.provenance) {
      writeJson(
        path.join(scenarioDir, "provenance.intoto.json"),
        result.proposed.evidence.provenance,
      );
    }
  }
}

function percentage(value) {
  return `${(value * 100).toFixed(1)} %`;
}

function printReport(firstRun, metrics) {
  console.log("\nPoC v2 - Gestión segura de dependencias\n");
  console.table(
    firstRun.map((result) => ({
      escenario: result.id,
      nombre: result.name,
      esperado: result.expectedDecision,
      inicial: result.baseline.decision,
      propuesto: result.proposed.decision,
      hallazgos: result.proposed.findings.length,
    })),
  );
  console.log("Indicadores calculados:");
  console.log(
    `- Detección de riesgos, flujo inicial: ${percentage(metrics.baselineRiskDetectionRate)}`,
  );
  console.log(
    `- Detección de riesgos, flujo propuesto: ${percentage(metrics.proposedRiskDetectionRate)}`,
  );
  console.log(
    `- Exactitud de las decisiones: ${percentage(metrics.decisionAccuracy)}`,
  );
  console.log(
    `- Tasa de falsos positivos: ${percentage(metrics.cleanFalsePositiveRate)}`,
  );
  console.log(
    `- Reproducibilidad en ${REPETITIONS} ejecuciones: ${percentage(metrics.reproducibilityRate)}`,
  );
  console.log(
    `- Completitud de evidencias: ${percentage(metrics.evidenceCompletenessRate)}`,
  );
  console.log(
    `\nInforme JSON: ${path.join(OUTPUT_DIR, "results.json")}`,
  );
  console.log(`Resumen CSV: ${path.join(OUTPUT_DIR, "summary.csv")}`);
}

function main() {
  const policy = readJson("config/policy.json");
  const scenarios = readJson("data/scenarios.json");
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const runs = Array.from({ length: REPETITIONS }, (_, index) =>
    scenarios.map((scenario) => makeResult(scenario, policy, index + 1)),
  );
  const firstRun = runs[0];
  const metrics = calculateMetrics(firstRun, runs);

  writeEvidence(firstRun);
  writeSummaryCsv(firstRun);

  const result = {
    metadata: {
      name: "PoC v2 de gestión segura de dependencias",
      version: "2.0.0",
      repetitions: REPETITIONS,
      executedAt: new Date().toISOString(),
      policySha256: sha256(policy),
      dataSourceNote:
        "Datos controlados y congelados. La referencia NVD se utiliza como muestra y no se consulta en línea.",
      disclaimer:
        "Validación experimental en entorno controlado; no equivale a una certificación ni a un despliegue productivo.",
    },
    policy,
    scenarios: firstRun,
    metrics,
  };

  writeJson(path.join(OUTPUT_DIR, "results.json"), result);

  if (!quiet) {
    printReport(firstRun, metrics);
  }

  const passed =
    metrics.proposedRiskDetectionRate === 1 &&
    metrics.decisionAccuracy === 1 &&
    metrics.cleanFalsePositiveRate === 0 &&
    metrics.reproducibilityRate === 1 &&
    metrics.evidenceCompletenessRate === 1;

  if (!passed) {
    process.exitCode = 1;
  }
}

main();
