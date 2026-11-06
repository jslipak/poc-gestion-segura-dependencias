# PoC de gestión segura de dependencias

La ejecución principal genera escenarios de laboratorio S0–S9 y los valida con
controles del proyecto y Trivy. El modo simulado, disponible explícitamente,
conserva los datos controlados para las pruebas deterministas del motor de
políticas. Los scripts de ciclo de vida de las dependencias no se ejecutan.

## Requisitos

- Node.js 18 o superior y npm.
- Trivy. La POC se verificó con Trivy 0.76.2.
- Conexión a internet para consultar el registro npm y actualizar la base de
  vulnerabilidades de Trivy durante el ensayo real.

## 1. Instalar Trivy

Usa las instrucciones oficiales para consultar otras opciones o versiones:
[Instalación de Trivy](https://trivy.dev/docs/latest/getting-started/installation/).

### Linux (instalador oficial)

Este comando instala la versión probada en `/usr/local/bin`:

```sh
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin v0.76.2
```

En Debian o Ubuntu también se puede instalar desde el repositorio oficial de
Aqua:

```sh
sudo apt-get update
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

### macOS

Con Homebrew:

```sh
brew install trivy
```

### Windows

1. Abre la [página oficial de releases](https://github.com/aquasecurity/trivy/releases/latest).
2. Descarga el ZIP de Windows de 64 bits (`trivy_<versión>_windows-64bit.zip`).
3. Extrae el ZIP, por ejemplo, en `C:\Tools\Trivy`.
4. Abre Inicio y busca **Editar las variables de entorno del sistema**.
5. En **Variables de entorno**, selecciona `Path` en las variables de usuario,
   pulsa **Editar**, luego **Nuevo**, agrega `C:\Tools\Trivy` y confirma los
   cambios.
6. Cierra y vuelve a abrir PowerShell para que cargue el nuevo `PATH`.

### Comprobar la instalación

En Linux o macOS:

```sh
trivy --version
```

En PowerShell:

```powershell
trivy --version
```

La primera ejecución puede descargar la base de vulnerabilidades de Trivy; por
eso necesita acceso a internet.

## 2. Ejecutar la POC

Desde la carpeta `poc_gestion_dependencias`:

```sh
npm run poc
```

Si estás en la raíz del repositorio, usa `--prefix`:

```sh
npm --prefix poc_gestion_dependencias run poc
```

Ese comando ejecuta el modo real: genera los fixtures, aplica los controles y
llama a Trivy. Para ejecutar también las pruebas automáticas:

```sh
npm run validate
```

Si Trivy está instalado, pero no está en el `PATH`, indica la ruta del
ejecutable.

Linux o macOS:

```sh
TRIVY_BIN="/ruta/a/trivy" npm run poc
```

PowerShell:

```powershell
$env:TRIVY_BIN = "C:\Tools\Trivy\trivy.exe"
npm run poc
```

El script de Windows `ejecutar-prueba.cmd` comprueba que Node.js y Trivy estén
disponibles y luego ejecuta la POC y las pruebas.

### Ejecutar con Docker Compose

Desde la raíz del repositorio, Docker Compose construye una imagen liviana con
Node.js Alpine y Trivy incluido. No hace falta instalar Trivy en el equipo:

```sh
docker compose up
```

El archivo raíz `compose.yaml` construye usando esta carpeta como contexto y
encuentra el `Dockerfile` ubicado aquí. En la primera ejecución de otra máquina,
Compose descarga las imágenes base y crea localmente la imagen de la PoC; hay
que llevar el repositorio completo, no solo `compose.yaml`.

Para reconstruir la imagen después de cambiar el `Dockerfile`:

```sh
docker compose up --build
```

La ejecución es el modo real. La carpeta local
`poc_gestion_dependencias/output/` recibe los resultados y las evidencias; los
volúmenes `trivy-cache` y `npm-cache` conservan las cachés entre ejecuciones.
El contenedor ejecuta una sola corrida (`node index.js --real`), no levanta un
servicio en segundo plano y termina cuando acaba el ensayo. Se vinculan en
solo lectura `index.js`, `config/`, `data/` y `src/` desde la carpeta del
proyecto, así que usa las mismas definiciones que la ejecución local. Los
resultados permanecen en la carpeta existente `output/` del proyecto.

Compose muestra la salida en la terminal y devuelve el estado de la corrida.
Si necesitas interrumpirla antes de que termine, usa `Ctrl+C`.
En Linux, si tu usuario no tiene UID/GID 1000, puedes ejecutar
`LOCAL_UID=$(id -u) LOCAL_GID=$(id -g) docker compose up` para conservar la
propiedad de los archivos generados.

### Ejecutar Trivy directamente

Para escanear un proyecto npm propio, ejecuta primero la instalación segura de
sus dependencias desde la carpeta que contiene `package-lock.json`, de modo que
el analizador de licencias pueda inspeccionarlas:

```sh
npm ci --ignore-scripts --no-audit
trivy fs --scanners vuln,license --format table .
```

Para volver a escanear el fixture Maven S1 que genera la POC:

```sh
trivy fs --scanners vuln --format table output/real-run/projects/S1
```

### Modo simulado

El modo simulado carga un archivo JSON independiente por escenario desde
`data/scenarios/` (`S0.json`–`S9.json`); así, cada caso se puede revisar y
modificar por separado. Estos datos no sustituyen los resultados de Trivy. Se
ejecuta por separado:

```sh
npm run poc:simulated
npm run validate:simulated
```

## Escenarios reales

| Código | Escenario | Decisión esperada | Validación principal |
|---|---|---|---|
| S0 | Caso limpio | Permitir | Dependencia vigente; controles de origen, licencia, antigüedad, integridad, scripts y Trivy. |
| S1 | Vulnerabilidad crítica | Bloquear | Trivy sobre un proyecto Maven con `log4j-core:2.14.1`. |
| S2 | Registro no autorizado | Bloquear | Configuración npm efectiva y hosts del lockfile comparados con la política; se bloquea antes de instalar. |
| S3 | Lockfile inconsistente | Bloquear | `npm ci --ignore-scripts --no-audit`; se diferencia el error del lockfile de un fallo de red. |
| S4 | Script no autorizado | Bloquear | Inspección estática de `postinstall`; marcador ausente porque el script no se ejecuta. |
| S5 | Artefacto alterado | Bloquear | Integridad publicada por npm frente al `.tgz` original y una copia modificada. |
| S6 | Falta de mantenimiento | Revisión manual | Fecha del último release consultada al registro npm; es una señal, no prueba de abandono. |
| S7 | Licencia no permitida | Bloquear | Trivy analiza la licencia de una dependencia instalada con scripts deshabilitados. |
| S8 | Vulnerabilidad alta | Revisión manual | Trivy identifica vulnerabilidades altas sin una regla de bloqueo adicional. |
| S9 | Condiciones combinadas | Bloquear | Se conservan todos los hallazgos y prevalece cualquier condición bloqueante. |

S0 toma la versión latest de `chalk` en el registro npm al iniciar el ensayo y
la fija en su lockfile. La versión, los metadatos y el lockfile usados quedan
registrados para poder revisar el resultado. S1 usa Maven para que Log4j no
aparezca como una dependencia npm.

## Resultados y evidencias

El ensayo real escribe:

- `output/real-run/results.json`: decisión esperada y obtenida, hallazgos,
  versiones de Node.js/npm/Trivy y fechas/versión de la base de vulnerabilidades.
- `output/real-run/summary.csv`: resumen por escenario.
- `output/real-run/projects/`: manifiestos, lockfiles y proyectos generados.
- `output/real-run/evidence/`: por escenario, `trivy-execution.json` registra
  comando y código de salida; `trivy-report.json` conserva la salida original
  con DataSource, URLs y referencias de cada vulnerabilidad. El resumen de
  consola también muestra la base consultada y los enlaces de procedencia.
- `output/real-run/artifacts/`: artefacto original y copia alterada de S5.

Los `node_modules` temporales se eliminan al finalizar el ensayo; los
manifiestos, lockfiles y reportes permanecen. El modo simulado guarda sus
resultados en `output/results.json`, `output/summary.csv` y `output/evidence/`;
allí también genera SBOM CycloneDX y procedencia in-toto/SLSA.

## Alcance

La ejecución real es experimental: los hallazgos dependen de las versiones de
los paquetes y de la base Trivy registradas en el informe. El escenario S4
demuestra el bloqueo preventivo de scripts, no la detección de malware. El
modo simulado sirve para reproducir las pruebas del motor, pero sus datos no
deben presentarse como resultados de un escáner real.

La correspondencia final entre la política y la tesis debe revisarse contra el
texto de la tesis y su metodología.
