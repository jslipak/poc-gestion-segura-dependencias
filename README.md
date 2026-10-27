# Prueba de concepto: gestión segura de dependencias

## Explicación sencilla

Un programa suele usar piezas hechas por otras personas. A esas piezas se las
llama **dependencias**. Esta prueba de concepto funciona como un inspector:
lee una ficha de cada pieza, aplica unas reglas y decide si puede pasar, debe
detenerse o necesita que una persona la revise.

La prueba usa diez ejemplos preparados (S0–S9). No descarga ni ejecuta paquetes
reales. Así se puede repetir sin conectarse a servicios externos ni poner en
riesgo el equipo.

## Qué hace y qué no hace

- **Permitir:** el ejemplo no activa ninguna regla de bloqueo o revisión.
- **Bloquear:** el ejemplo tiene una señal que la política considera inaceptable.
- **Revisión manual:** hace falta que una persona mire el caso antes de decidir.

La PoC comprueba procedencia, archivo de bloqueo, vulnerabilidades, scripts,
integridad, mantenimiento y licencia. También genera una SBOM y archivos de
evidencia demostrativos. No reemplaza un escáner profesional, no consulta NVD
en línea y no demuestra que una aplicación real esté protegida.

## Cómo ejecutarla

Necesitas **Node.js 18 o superior**. No necesitas instalar paquetes ni
bibliotecas adicionales.

1. Clona el repositorio:

```sh
git clone https://github.com/jslipak/poc-gestion-segura-dependencias.git
```

2. Entra a la carpeta del programa:

```sh
cd poc-gestion-segura-dependencias/poc_gestion_dependencias
```

3. Ejecuta el programa y las pruebas:

```sh
node index.js
node --test test/policy-engine.test.js
```

También puedes ejecutar `npm run validate` si tienes npm. En Windows puedes
iniciar la prueba con doble clic en `ejecutar-prueba.cmd`.

## Ejemplos y resultados esperados

Los datos de entrada están en `poc_gestion_dependencias/data/scenarios.json` y
las reglas en `poc_gestion_dependencias/config/policy.json`.

| Escenario | Ejemplo | Decisión esperada |
|---|---|---|
| S0 | Pieza sin señales de riesgo | Permitir |
| S1 | Vulnerabilidad crítica conocida | Bloquear |
| S2 | Registro no autorizado | Bloquear |
| S3 | Archivo de bloqueo inconsistente | Bloquear |
| S4 | Script de instalación no autorizado | Bloquear |
| S5 | Huella del artefacto diferente | Bloquear |
| S6 | Proyecto sin mantenimiento reciente | Revisión manual |
| S7 | Licencia no permitida | Bloquear |
| S8 | Vulnerabilidad que requiere contexto | Revisión manual |
| S9 | Varias señales de riesgo juntas | Bloquear |

En la ejecución documentada, el flujo inicial dejó pasar los nueve casos con
riesgo. El flujo propuesto bloqueó siete, envió dos a revisión manual y permitió
el caso limpio. Las seis pruebas automáticas finalizaron correctamente. Estos
resultados corresponden únicamente a estos ejemplos controlados.

## Dónde mirar las evidencias

Después de ejecutar `node index.js`, revisa `poc_gestion_dependencias/output/`:

- `results.json` resume la ejecución.
- `summary.csv` presenta un resumen en tabla.
- `evidence/S0/` a `evidence/S9/` contienen los informes de cada ejemplo.
- `policy-report.json` explica qué reglas se aplicaron.
- `sbom.cdx.json` muestra el inventario demostrativo de componentes.
- `evidence-manifest.json` registra huellas SHA-256 de archivos.
- `provenance.intoto.json`, cuando se genera, es una declaración demostrativa
  sin firma criptográfica.

El campo `executedAt` hace que `results.json` tenga una fecha distinta en cada
ejecución. Por eso, al comparar ejecuciones, compara las decisiones y los
informes por escenario; no esperes que todos los archivos tengan el mismo hash.

## Versión evaluada y ZIP de referencia

El código y la política evaluados son la versión **2.0.0**. El ZIP original se
conserva como `poc_adv_ejecutado.zip`; su SHA-256 es:

```text
6dfb1f88b5d4dcc720efe193c683c019f1541196cd6d28df231213985f9adb82
```

El ZIP es un archivo de referencia. El repositorio también contiene el código
extraído para que se pueda leer y ejecutar con facilidad. La tesis documenta
los comandos, los resultados y las limitaciones de esta prueba.

## Demostración breve

En unos minutos se puede revisar `config/policy.json`, elegir un escenario,
ejecutar los dos comandos anteriores y abrir las evidencias de S0, S1 y S5.
Para coordinar una demostración en vivo, se puede acordar un horario con el
autor de la tesis.
