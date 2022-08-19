@echo off
setlocal
setlocal EnableDelayedExpansion
@title Collection Tool v19.1
:: 
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::  Collection.cmd  		v19.1
::  	- driver script for Collection_main.js  
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

pushd "%~dp0"

:Collection
cscript.exe Collection_main.js %*
@title Command Prompt

:endlocalvars
endlocal
popd
:EOF