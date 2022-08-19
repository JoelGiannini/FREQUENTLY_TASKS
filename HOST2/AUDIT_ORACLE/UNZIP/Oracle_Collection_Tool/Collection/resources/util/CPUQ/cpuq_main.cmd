echo off
SetLocal EnableDelayedExpansion
SetLocal EnableExtensions

set "current_dir=%cd%"
set "working_dir=..\resources\util\CPUQ"
set "output_dir=%CT_TMP%\CPUQ"
set "logs_dir=%CT_TMP%\logs"

if not exist "%output_dir%" ( mkdir "%output_dir%" ) 
if not exist "%logs_dir%" ( mkdir "%logs_dir%" ) 

cd "%working_dir%"
call ct_cpuq.cmd %output_dir%

cd /d "%output_dir%"

For /F "delims=" %%a in ('type *-ct_cpuq.txt ^| findstr /B /C:"Computer Name:"') do (
	set v_collected=%%a
	set v_collected=!v_collected:Computer Name: =!
	echo CPUQ: CT-01000: COLLECTED: Machine Name: !v_collected! >> "%logs_dir%\CPUQ_collected.log"
	)

	 
For /F "delims=" %%a in ('type *-ct_cpuq.txt ^| findstr /B /R /C:"CPUQ: CT-[0-9]*: WARNING:"') do (
	set v_collected=%%a
	echo %v_collected% >> "%logs_dir%\CPUQ_warnings.log"
	 )	 

For /F "delims=" %%a in ('type *-ct_cpuq.txt ^| findstr /B /R /C:"CPUQ: CT-[0-9]*: ERROR:"') do (
	set v_collected=%%a
	echo %v_collected% >> "%logs_dir%\CPUQ_errors.log"
	 )	 

EndLocal