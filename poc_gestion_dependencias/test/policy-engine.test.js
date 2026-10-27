"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const {
  evaluateProposed,
  calculateMetrics,
  sha256,
} = require("../src/policy-engine");

const ROOT = path.resolve(__dirname, "..");
const policy = JSON.parse(
  fs.readFileSync(path.join(ROOT, "config", "policy.json"), "utf8"),
);
const scenarios = JSON.parse(
  fs.readFileSync(path.join(ROOT, "data", "scenarios.json"), "utf8"),
);

function resultFor(scenario, repetition = 1) {
  return {
    id: scenario.id,
    name: scenario.name,
    repetition,
    containsRisk: scenario.containsRisk,
    expectedDecision: scenario.expectedDecision,
    baseline: {
      decision: scenario.manifestValid ? "permitir" : "bloquear",
      findings: [],
    },
    proposed: evaluateProposed(scenario, policy),
  };
}

test("todos los escenarios producen la decisión esperada", () => {
  assert.equal(scenarios.length, 10);
  for (const scenario of scenarios) {
    assert.equal(
      evaluateProposed(scenario, policy).decision,
      scenario.expectedDecision,
      scenario.id,
    );
  }
});

test("el control limpio no genera falsos positivos", () => {
  const clean = scenarios.find((scenario) => scenario.id === "S0");
  const result = evaluateProposed(clean, policy);
  assert.equal(result.decision, "permitir");
  assert.deepEqual(result.findings, []);
});

test("la alteración del artefacto se detecta mediante SHA-256", () => {
  const clean = scenarios.find((scenario) => scenario.id === "S0");
  const tampered = {
    ...clean,
    actualArtifactContent: `${clean.actualArtifactContent}-alterado`,
  };
  const result = evaluateProposed(tampered, policy);
  assert.equal(result.decision, "bloquear");
  assert.ok(
    result.findings.some((finding) => finding.control === "integridad"),
  );
});

test("los umbrales CVSS distinguen bloqueo, revisión y aceptación", () => {
  const clean = scenarios.find((scenario) => scenario.id === "S0");
  const withCvss = (cvss) => ({
    ...clean,
    vulnerabilities: [
      {
        id: `CVE-TEST-${cvss}`,
        source: "prueba",
        cvss,
        knownExploited: false,
      },
    ],
  });
  assert.equal(evaluateProposed(withCvss(9), policy).decision, "bloquear");
  assert.equal(
    evaluateProposed(withCvss(7), policy).decision,
    "revision_manual",
  );
  assert.equal(evaluateProposed(withCvss(6.9), policy).decision, "permitir");
});

test("la SBOM y el manifiesto de evidencias contienen datos verificables", () => {
  const clean = scenarios.find((scenario) => scenario.id === "S0");
  const result = evaluateProposed(clean, policy);
  assert.equal(result.evidence.sbom.bomFormat, "CycloneDX");
  assert.equal(result.evidence.sbom.specVersion, "1.6");
  assert.match(result.evidence.manifest.sbom, /^[a-f0-9]{64}$/);
  assert.equal(
    result.evidence.manifest.sbom,
    sha256(result.evidence.sbom),
  );
  assert.ok(result.evidence.provenance);
});

test("cinco ejecuciones idénticas son reproducibles", () => {
  const runs = Array.from({ length: 5 }, (_, index) =>
    scenarios.map((scenario) => resultFor(scenario, index + 1)),
  );
  const metrics = calculateMetrics(runs[0], runs);
  assert.equal(metrics.proposedRiskDetectionRate, 1);
  assert.equal(metrics.decisionAccuracy, 1);
  assert.equal(metrics.cleanFalsePositiveRate, 0);
  assert.equal(metrics.reproducibilityRate, 1);
  assert.equal(metrics.evidenceCompletenessRate, 1);
});
