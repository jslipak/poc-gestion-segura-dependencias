"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  classifyNpmCiResult,
  decisionForFindings,
  isApprovedRegistry,
  trivyFindings,
} = require("../src/real-runner");

test("la política reconoce hosts autorizados y rechaza hosts parecidos", () => {
  assert.equal(isApprovedRegistry("https://registry.npmjs.org/"), true);
  assert.equal(isApprovedRegistry("https://registry.npmjs.org:444/"), false);
  assert.equal(isApprovedRegistry("http://registry.npmjs.org/"), false);
  assert.equal(isApprovedRegistry("https://registry.npmjs.org.evil.invalid/"), false);
  assert.equal(isApprovedRegistry("not-a-url"), false);
});

test("npm ci distingue una inconsistencia del lockfile de un error de red", () => {
  assert.equal(
    classifyNpmCiResult({
      exitCode: 1,
      stdout: "",
      stderr: "npm ci can only install packages when your package.json and package-lock.json are in sync",
    }),
    "lockfile_inconsistent",
  );
  assert.equal(
    classifyNpmCiResult({ exitCode: 1, stdout: "", stderr: "ECONNRESET" }),
    "network_error",
  );
  assert.equal(classifyNpmCiResult({ exitCode: 0 }), "success");
});

test("el parser de Trivy conserva CVSS, licencia y severidad del hallazgo", () => {
  const parsed = trivyFindings({
    Results: [
      {
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-TEST-1",
            PkgName: "sample",
            InstalledVersion: "1.0.0",
            Severity: "HIGH",
            CVSS: { nvd: { V3Score: 7.5 } },
          },
        ],
        Packages: [
          {
            Name: "sample",
            Version: "1.0.0",
            Licenses: ["GPL-3.0-only"],
          },
        ],
      },
    ],
  });

  assert.equal(parsed.vulnerabilities[0].id, "CVE-TEST-1");
  assert.equal(parsed.vulnerabilities[0].cvss, 7.5);
  assert.equal(parsed.vulnerabilities[0].controlSeverity, "advertencia");
  assert.ok(parsed.licenses.some((license) => license.name === "GPL-3.0-only"));
});

test("una condición bloqueante prevalece sobre revisión manual", () => {
  assert.equal(
    decisionForFindings([
      { severity: "advertencia" },
      { severity: "bloqueante" },
    ]),
    "bloquear",
  );
  assert.equal(decisionForFindings([{ severity: "advertencia" }]), "revision_manual");
});

test("el umbral prefiere CVSS v3 cuando Trivy incluye también CVSS v2", () => {
  const parsed = trivyFindings({
    Results: [
      {
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-TEST-VERSIONS",
            PkgName: "sample",
            InstalledVersion: "1.0.0",
            Severity: "MEDIUM",
            CVSS: { nvd: { V2Score: 9.0, V3Score: 6.6 } },
          },
        ],
      },
    ],
  });
  assert.equal(parsed.vulnerabilities[0].cvss, 6.6);
  assert.equal(parsed.vulnerabilities[0].controlSeverity, "informativo");
});
