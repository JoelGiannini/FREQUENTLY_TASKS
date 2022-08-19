@echo off
set SCRIPT_VERSION="19.1"!CT_BUILD_VERSION!
setlocal
setlocal EnableDelayedExpansion
echo "Starting run_opmnctl_status.cmd script"
if not exist "!CT_TMP!\FMW\" mkdir "!CT_TMP!\FMW\"
set CT_OPMN_TEMPFILE="!CT_TMP!\%COMPUTERNAME%-opmnctl_locations.txt"
set CT_OPMN_OUT_FILE="!CT_TMP!\FMW\%COMPUTERNAME%-opmn_output.txt"
findstr "bin\\opmnctl.exe bin\\opmnctl.bat" !CT_TMP!\logs\CTfiles.txt | findstr /v "tmplt" > %CT_OPMN_TEMPFILE%
echo "SCRIPT_VERSION = %SCRIPT_VERSION%" > %CT_OPMN_OUT_FILE%
echo ============================================================================= >> %CT_OPMN_OUT_FILE%
SET /a c=0
for /F "tokens=*" %%a in ('type %CT_OPMN_TEMPFILE%') do (
	set /a c=c+1
	set string1=%%a
	set string2=!string1:\opmn\bin\opmnctl.bat=!
	set string3=!string2:\bin\opmnctl.bat=!
	echo Home!c!:  !string3! >> %CT_OPMN_OUT_FILE%
	echo ---------------- >> %CT_OPMN_OUT_FILE%
	cmd /c %%a status >> %CT_OPMN_OUT_FILE% 2>&1
	echo ============================================================================= >> %CT_OPMN_OUT_FILE%
)
if exist %CT_OPMN_TEMPFILE% del %CT_OPMN_TEMPFILE%
endlocal