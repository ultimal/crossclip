@echo off
setlocal

set SCRIPT_DIR=%~dp0

if exist "%SCRIPT_DIR%build" (
    echo Removing "%SCRIPT_DIR%build"...
    rmdir /s /q "%SCRIPT_DIR%build"
)

echo Clean complete.
