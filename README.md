# Prueba de concepto: gestión segura de dependencias

La ejecución principal genera fixtures versionados para S0–S9 y valida los
controles con Trivy. Conserva los lockfiles y reportes originales para repetir
cada ensayo, y deshabilita scripts de instalación. El modo simulado
(`poc:simulated`) se mantiene para las pruebas deterministas; sus datos no son
resultados de Trivy.

La guía completa de instalación, ejecución y evidencias está en
[`poc_gestion_dependencias/README.md`](poc_gestion_dependencias/README.md).

## Requisitos

- Node.js 18 o superior y npm.
- Trivy; la ejecución fue verificada con la versión 0.76.2.
- Internet para npm y para actualizar la base de vulnerabilidades de Trivy.

## Instalar Trivy

Consulta las [instrucciones oficiales](https://trivy.dev/docs/latest/getting-started/installation/).

En Linux, el instalador oficial instala la versión probada:

```sh
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin v0.76.2
```

En macOS se puede usar `brew install trivy`. En Windows, descarga el ZIP de
64 bits desde la [página oficial de releases](https://github.com/aquasecurity/trivy/releases/latest),
extráelo y agrega la carpeta que contiene `trivy.exe` al `PATH`. Luego cierra y
vuelve a abrir la terminal.

Comprueba que quedó instalado:

```sh
trivy --version
```

La guía del proyecto contiene los pasos detallados para Debian/Ubuntu, macOS y
Windows.

## Ejecutar

Desde la carpeta del proyecto:

```sh
cd poc_gestion_dependencias
npm run poc
```

Para ejecutar también las 11 pruebas automáticas:

```sh
npm run validate
```

El modo real es el predeterminado. Para ejecutar los datos simulados:

```sh
npm run poc:simulated
npm run validate:simulated
```

En Windows se puede iniciar `poc_gestion_dependencias/ejecutar-prueba.cmd`;
requiere que Node.js y Trivy estén disponibles.

## Escenarios y resultados

| Escenario | Control demostrado | Decisión esperada |
|---|---|---|
| S0 | Proyecto limpio, dependencias que cumplen la política | Permitir |
| S1 | Vulnerabilidad crítica; proyecto Maven con `log4j-core:2.14.1` | Bloquear |
| S2 | Registro npm no autorizado en configuración y lockfile | Bloquear antes de instalar |
| S3 | Manifiesto y lockfile inconsistentes | Bloquear con `npm ci` |
| S4 | `postinstall` detectado sin ejecutarlo | Bloquear |
| S5 | `.tgz` original contra copia alterada e integridad publicada | Bloquear la copia alterada |
| S6 | Antigüedad real del release | Revisión manual |
| S7 | Licencia fuera de política, detectada por Trivy | Bloquear |
| S8 | Vulnerabilidad alta sin otra regla bloqueante | Revisión manual |
| S9 | Vulnerabilidad, fuente no autorizada e integridad alterada | Bloquear |

Los resultados del modo real se guardan en
`poc_gestion_dependencias/output/real-run/`: `results.json`, `summary.csv`,
proyectos de laboratorio, reportes originales de Trivy y un manifiesto SHA-256.
La versión de Trivy, la fecha de la ejecución y la versión de su base quedan en
el informe. Las decisiones pueden variar cuando se actualicen sus fuentes.

El modo simulado conserva sus salidas en `poc_gestion_dependencias/output/`;
genera datos de prueba, SBOM CycloneDX y procedencia demostrativa. No se deben
presentar esos valores simulados como hallazgos de un escáner.

## Alcance

Es una evaluación experimental, no una certificación ni un control de
producción. S4 demuestra prevención de ejecución de scripts, no detección de
malware. La coherencia final de política, métricas y conclusiones debe
contrastarse con la tesis.

## ZIP de referencia

El ZIP original se conserva como `poc_adv_ejecutado.zip`; su SHA-256 es:

```text
6dfb1f88b5d4dcc720efe193c683c019f1541196cd6d28df231213985f9adb82
```
