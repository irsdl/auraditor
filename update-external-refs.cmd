@echo off
REM Update External Reference Repositories
REM This script updates the git submodules in external-refs/ to their latest versions

echo Updating external reference repositories...
echo.

echo Updating Montoya API...
git submodule update --remote external-refs/montoya-api
if %errorlevel% neq 0 (
    echo ERROR: Failed to update Montoya API
    exit /b 1
)

echo.
echo Updating Montoya API Examples...
git submodule update --remote external-refs/montoya-api-examples
if %errorlevel% neq 0 (
    echo ERROR: Failed to update Montoya API Examples
    exit /b 1
)

echo.
echo ========================================
echo All external references updated successfully!
echo ========================================
echo.
echo To commit the updates, run:
echo   git add external-refs/
echo   git commit -m "Update external reference repositories"
echo.
