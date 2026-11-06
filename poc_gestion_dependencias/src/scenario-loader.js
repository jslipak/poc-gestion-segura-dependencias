"use strict";

const fs = require("fs");
const path = require("path");

const SCENARIOS_DIR = path.join(__dirname, "..", "data", "scenarios");

function loadScenarios() {
  const scenarioFiles = fs
    .readdirSync(SCENARIOS_DIR)
    .filter((fileName) => fileName.endsWith(".json"))
    .sort((left, right) => left.localeCompare(right, "en", { numeric: true }));

  return scenarioFiles.map((fileName) => {
    const scenario = JSON.parse(
      fs.readFileSync(path.join(SCENARIOS_DIR, fileName), "utf8"),
    );
    const expectedId = path.basename(fileName, ".json");
    if (scenario.id !== expectedId) {
      throw new Error(
        `El ID del escenario en ${fileName} debe ser ${expectedId}.`,
      );
    }
    return scenario;
  });
}

module.exports = { loadScenarios };
