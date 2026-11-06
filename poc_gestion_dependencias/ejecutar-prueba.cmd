@echo off
chcp 65001 >nul
pushd "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: no se encontro Node.js. Instale Node.js 18 o superior.
  popd
  pause
  exit /b 1
)

if not defined TRIVY_BIN (
  where trivy >nul 2>nul
  if errorlevel 1 (
    echo ERROR: no se encontro Trivy. Instale Trivy o configure TRIVY_BIN.
    popd
    pause
    exit /b 1
  )
)

echo Ejecutando la PoC...
node index.js --real
if errorlevel 1 (
  echo.
  echo La ejecucion de escenarios fallo.
  popd
  pause
  exit /b 1
)

echo.
echo Ejecutando pruebas automaticas...
node --test
set "POC_RESULT=%ERRORLEVEL%"

echo.
if "%POC_RESULT%"=="0" (
  echo RESULTADO: todas las validaciones fueron superadas.
) else (
  echo RESULTADO: una o mas validaciones fallaron.
)

popd
pause
exit /b %POC_RESULT%
