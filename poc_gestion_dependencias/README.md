# PoC v2 de gestión segura de dependencias

Esta prueba de concepto evalúa una estrategia de implementación basada en
controles existentes para la gestión segura de dependencias. Compara un flujo
inicial limitado a procesar el manifiesto con un flujo propuesto que aplica
políticas, produce una SBOM y conserva evidencias verificables.

La PoC no descarga ni ejecuta paquetes vulnerables. Utiliza escenarios
controlados para que la demostración sea segura, repetible y no dependa de
cambios diarios en fuentes externas.

## Requisitos

- Node.js 18 o superior.
- No requiere instalar bibliotecas externas.

## Ejecución

La forma más sencilla en Windows es hacer doble clic en:

```text
ejecutar-prueba.cmd
```

También puede ejecutarse desde una terminal, sin utilizar npm:

```powershell
node index.js
node --test test\policy-engine.test.js
```

Si npm se encuentra disponible:

```powershell
npm run poc
```

Para ejecutar las pruebas automáticas:

```powershell
npm test
```

Para realizar ambas validaciones:

```powershell
npm run validate
```

## Controles implementados

1. Procedencia del paquete y registro autorizado.
2. Presencia y consistencia del archivo de bloqueo.
3. Vulnerabilidades y umbrales CVSS.
4. Identificación de vulnerabilidades explotadas.
5. Scripts de instalación o ciclo de vida.
6. Integridad real mediante SHA-256.
7. Antigüedad de mantenimiento.
8. Licencias permitidas.
9. Generación de SBOM en formato CycloneDX 1.6.
10. Generación de procedencia con estructura in-toto/SLSA.

## Escenarios experimentales

| Código | Escenario | Decisión esperada |
|---|---|---|
| S0 | Control limpio | Permitir |
| S1 | Vulnerabilidad crítica registrada en NVD | Bloquear |
| S2 | Registro no autorizado | Bloquear |
| S3 | Archivo de bloqueo inconsistente | Bloquear |
| S4 | Script de instalación no autorizado | Bloquear |
| S5 | Artefacto alterado | Bloquear |
| S6 | Componente sin mantenimiento | Revisión manual |
| S7 | Licencia no permitida | Bloquear |
| S8 | Vulnerabilidad alta | Revisión manual |
| S9 | Amenazas combinadas | Bloquear |

S1 emplea como muestra congelada `CVE-2021-44228`, identificada en NVD. La PoC
no consulta NVD en línea: la puntuación se mantiene fija para preservar la
reproducibilidad. Los identificadores `CVE-DEMO` son datos sintéticos y no deben
interpretarse como registros reales.

## Evidencias generadas

La carpeta `output` contiene:

- `results.json`: informe completo y métricas calculadas.
- `summary.csv`: resumen apto para incorporar a una tabla.
- `evidence/<escenario>/sbom.cdx.json`: SBOM de cada escenario.
- `evidence/<escenario>/policy-report.json`: controles y hallazgos.
- `evidence/<escenario>/evidence-manifest.json`: hashes SHA-256.
- `evidence/<escenario>/provenance.intoto.json`: procedencia de los casos que
  pueden continuar.

## Demostración sugerida

1. Mostrar `config/policy.json` y explicar los umbrales.
2. Mostrar brevemente los escenarios de `data/scenarios.json`.
3. Ejecutar `npm run validate`.
4. Comparar las decisiones del flujo inicial y el propuesto.
5. Abrir las evidencias de S0, S1 y S5.
6. Aclarar que la validación es experimental y controlada.

## Alcance

Este código prueba la lógica de integración propuesta, pero no reemplaza una
herramienta SCA, un motor de políticas empresarial ni una consulta en línea a
NVD. En producción, las entradas controladas se sustituirían por datos del
gestor de paquetes, una fuente de vulnerabilidades, un generador de SBOM, un
servicio de firma y el pipeline de construcción.
