@Echo off
SetLocal EnableDelayedExpansion 
SetLocal EnableExtensions

rem Setting working directory

echo !CT_TMP!
set "CT_OUTPUT=!CT_TMP!"

set "CT_TMP_DB=!CT_TMP!CTDB"

if not exist "%CT_TMP_DB%" ( mkdir "%CT_TMP_DB%" )

rem if not exist "%CT_OUTPUT%" ( mkdir "%CT_OUTPUT%" )

set "CT_HOME=%CD%"
set "CT_EXEC_HOME=%CT_HOME%\..\resources\util\db"

rem Copying sql and cmd files
copy "%CT_EXEC_HOME%"\*.sql "%CT_TMP_DB%"
copy "%CT_EXEC_HOME%"\*.cmd "%CT_TMP_DB%"

set "SQLSCRIPT=db_conn_coll_main.sql"
set "REMOTE_DB=!REMOTE_DB!"
set "DB_CT_BUILD_VERSION=!CT_BUILD_VERSION!"
set "DBLICAGREE=!LICAGREE!"
if "%DBLICAGREE%" == "True" ( set "DBLICAGREE=YES" ) else (
								set "DBLICAGREE=NO" )
							
set "DBALLPRODLIST=!ALLPRODLIST!"

IF /i "%DBALLPRODLIST:EBS=%"=="%DBALLPRODLIST%" ( set "DBALLPRODLIST=DB" ) else ( set "DBALLPRODLIST=EBS~DB" ) 

set "current_dir=%CT_OUTPUT%"
set "working_dir=%CT_TMP_DB%"
set "DB_output_dir=%CT_OUTPUT%DB"
set "EBS_output_dir=%CT_OUTPUT%EBS"
set "DBA_FUS_output_dir=%CT_OUTPUT%DBA_FUS"
set "logs_output_dir=%CT_OUTPUT%logs"

if not exist "%logs_output_dir%" ( mkdir "%logs_output_dir%" )
if exist "%logs_output_dir%\DB_*.log"  ( del "%logs_output_dir%\DB_*.log")
if exist "%logs_output_dir%\EBS_*.log" ( del "%logs_output_dir%\EBS_*.log")

cd /d "%working_dir%"

set "mypath=%cd%"
	
	if exist db_con_coll.log (type db_con_coll.log >>db_con_coll.temp )
	if exist *.txt (del *.txt)
	if exist *.log (del *.log)
	
	echo Script version= %DB_CT_BUILD_VERSION% >> db_con_coll.log
	echo %COMPUTERNAME%>>db_con_coll.log 
	
    call look_for_running_sids.cmd %SQLSCRIPT% %DBLICAGREE% %DBALLPRODLIST%
	call db_conn_coll.cmd y db_list.csv
	
	dir /s >> db_con_coll.log
	
	call logcolstat.cmd DB YES	
	
	if exist "%mypath%\DB" (
	cd DB
	if not exist "%DB_output_dir%" ( mkdir "%DB_output_dir%" ) 
    for /f "delims=" %%a in ( 'dir /ad /b /s' ) do (
		for /f "delims=" %%F in ("%%a") do  (
		if exist "%DB_output_dir%\%%~nxF" ( rd /S /Q "%DB_output_dir%\%%~nxF" )
		
		move   "%%a" "%DB_output_dir%"
		
		)	
	)
	cd ..
	)
	
	if exist "%mypath%\DBA_FUS" (
	cd DBA_FUS
	if not exist "%DBA_FUS_output_dir%" ( mkdir "%DBA_FUS_output_dir%" )
	  for /f "delims=" %%a in ( 'dir /ad /b /s' ) do (
		
		for /f "delims=" %%F in ("%%a") do  (
			if exist "%DBA_FUS_output_dir%\%%~nxF" ( rd /S /Q "%DBA_FUS_output_dir%\%%~nxF" )
			
		move   "%%a" "%DBA_FUS_output_dir%"
		
		)
	)
	cd ..
	)
	
	if exist "%mypath%\EBS" ( 	cd EBS
		if not exist "%EBS_output_dir%" ( mkdir "%EBS_output_dir%" ) 
		for /f "delims=" %%a in ( 'dir /ad /b /s' ) do (
			
			for /f "delims=" %%F in ("%%a") do  (
				if exist "%EBS_output_dir%\%%~nxF" ( rd /S /Q "%EBS_output_dir%\%%~nxF" )
				
			move   "%%a" "%EBS_output_dir%"
			
			)
		) 
	cd ..
	)
		
	rem remove deplicates
	if exist DB_errors.log ( if exist DB_collected.log (
	for /F "tokens=5" %%a in (DB_collected.log) do (
		type DB_errors.log |  findstr /V /I /C:" %%a " > err_tmp.log	
			)
		)
	move err_tmp.log DB_errors.log
	)
	 
	dir /s %current_dir%DB 	%current_dir%DBA_FUS	%current_dir%EBS  >> db_con_coll.log
	
	type db_con_coll.log >> db_con_coll.temp
	copy db_con_coll.temp db_con_coll.log
	del  db_con_coll.temp
	copy db_con_coll.log "!logs_output_dir!"
	copy db_list.csv "!logs_output_dir!" 
	del db_list.csv
	copy *.csv  %DB_output_dir%
	if exist DB_collected.log 		(copy DB_collected.log "!logs_output_dir!"	)
	if exist DB_errors.log 			(copy DB_errors.log "!logs_output_dir!"		)	
	if exist DB_warnings.log  		(copy DB_warnings.log "!logs_output_dir!"	)
	if exist EBS_collected.log 		(copy EBS_collected.log "!logs_output_dir!"	)
	if exist EBS_errors.log  		(copy EBS_errors.log "!logs_output_dir!"	)
	if exist EBS_warnings.log 		(copy EBS_warnings.log "!logs_output_dir!"	)
	del checkconn.txt
	
cd /d "%current_dir%"
	echo %cd%
	echo %CT_TMP_DB%
	rd /S /Q %CT_TMP_DB%


EndLocal
