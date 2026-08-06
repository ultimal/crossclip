@echo off
setlocal

set SCRIPT_DIR=%~dp0
set QT_PREFIX=C:/Qt/6.8.0/msvc2022_64
set CONFIG=Release

cmake -S "%SCRIPT_DIR%." -B "%SCRIPT_DIR%build" -DCMAKE_PREFIX_PATH="%QT_PREFIX%"
if errorlevel 1 (
    echo CMake configure failed.
    exit /b 1
)

cmake --build "%SCRIPT_DIR%build" --config %CONFIG%
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo Build complete: %SCRIPT_DIR%build\%CONFIG%\server.exe and client.exe
