# Tareas y mejoras de la POC

La matriz S0–S9 define los escenarios. El modo simulado usa un archivo JSON
por escenario en `data/scenarios/`; el modo real genera proyectos de laboratorio
y conserva por separado las evidencias del escáner.

## Pendiente

- [ ] **Tarea 2 — Mantener coherencia con la tesis:** verificar que escenarios, política, umbrales, métricas, decisiones y evidencias correspondan con la metodología y los objetivos de la tesis; documentar fuentes, supuestos y limitaciones.

La Tarea 2 requiere contrastar estos resultados con el texto y la metodología de la tesis.

## Completadas

- [x] **Tarea 1 — Generar escenarios reproducibles y validarlos con herramientas reales:** se implementó `npm run poc:real`; las versiones y lockfiles usados quedan guardados en `output/real-run/projects/`.
- [x] **Tarea 3 — Mostrar y guardar resultados:** la salida se presenta en consola y se guarda en `output/real-run/results.json` y `output/real-run/summary.csv`.
- [x] **Tarea 4 — Integrar Trivy:** se conserva versión, base de datos, código de salida y reportes JSON originales en `output/real-run/evidence/`.
- [x] **Tarea 5 — Separar simulación y ensayo real:** `npm run poc` ejecuta los fixtures reales; `npm run poc:simulated` mantiene el modo determinista separado.
- [x] **Tarea 6 — Completar la evidencia de resultados:** el informe incluye decisiones esperadas/obtenidas y hallazgos; el manifiesto de evidencias registra SHA-256 de entradas, reportes y salidas.
- [x] **Tarea 7 — Validar seguridad y reproducibilidad:** dependencias con scripts instaladas mediante `--ignore-scripts`; versiones y fecha registradas; `npm run validate:real` repetido con los diez escenarios aprobados.
- [x] **S0 — Caso limpio:** versión latest de `chalk` fijada en el lockfile de la ejecución; se verifican registry, licencia, antigüedad, integridad, scripts y Trivy antes de permitir.
- [x] **S1 — Vulnerabilidad crítica:** proyecto Maven con `log4j-core:2.14.1`; Trivy confirma `CVE-2021-44228` y el motor bloquea.
- [x] **S2 — Registro no autorizado:** configuración efectiva y URLs del lockfile comparadas contra la política; se bloquea sin intentar instalar dependencias.
- [x] **S3 — Lockfile inconsistente:** `npm ci` rechaza el cambio de manifiesto; el resultado se clasifica como inconsistencia y se conserva su salida.
- [x] **S4 — Script no autorizado:** `postinstall` detectado estáticamente; marcador ausente, lo que confirma que no se ejecutó.
- [x] **S5 — Artefacto alterado:** el `.tgz` original coincide con la integridad publicada por npm y la copia modificada no.
- [x] **S6 — Falta de mantenimiento:** fecha del último release de `request` consultada al registro npm; antigüedad deriva a revisión manual, no a bloqueo automático.
- [x] **S7 — Licencia no permitida:** Trivy detecta `GPL-3.0-only` en `@substrate/connect-known-chains`; el motor bloquea.
- [x] **S8 — Vulnerabilidad alta:** Trivy detecta hallazgos HIGH con CVSS 7.5 en `path-to-regexp@0.1.7`; el motor deriva a revisión manual.
- [x] **S9 — Condiciones combinadas:** Trivy, registro no autorizado e integridad alterada generan hallazgos simultáneos; prevalece bloquear.

Ensayo verificado con Node.js 24.21.0, npm 11.19.0 y Trivy 0.76.2; los detalles y la fecha de la base de vulnerabilidades están en `output/real-run/results.json`.
