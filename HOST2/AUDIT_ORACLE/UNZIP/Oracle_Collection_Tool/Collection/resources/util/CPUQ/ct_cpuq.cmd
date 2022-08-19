@echo off
:: ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::   ct_cpuq.cmd v.19.1
::    - grab cpu and machine info.
::
:: ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


SETLOCAL
if NOT [%CT_BUILD_VERSION%]==[] (
	goto main
	)

echo Terms for Oracle Software Collection Tool >"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo By selecting "Accept License Agreement" (or the equivalent) or by installing or using the Software (as defined below), You indicate Your acceptance of these terms and Your agreement, as an authorized representative of Your company or organization (if being acquired for use by an entity) or as an individual, to comply with the license terms that apply to the Software.  If you are not willing to be bound by these terms, do not indicate Your acceptance and do not download, install, or use the Software.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo License Agreement>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo PLEASE SCROLL DOWN AND READ ALL OF THE FOLLOWING TERMS AND CONDITIONS OF THIS LICENSE AGREEMENT (this "Agreement") CAREFULLY.  THIS AGREEMENT IS A LEGALLY BINDING CONTRACT BETWEEN YOU AND ORACLE AMERICA, INC. THAT SETS FORTH THE TERMS THAT GOVERN YOUR USE OF THE SOFTWARE. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo YOU MUST ACCEPT AND ABIDE BY THESE TERMS AS PRESENTED TO YOU - ANY CHANGES, ADDITIONS OR DELETIONS BY YOU TO THESE TERMS ARE NOT ACCEPTED  AND WILL NOT BE PART OF THIS AGREEMENT.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Definitions>>"%TEMP%\ct_cpuq_tmp.txt"
echo "Oracle" refers to Oracle America, Inc.. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo "You" and "Your" refers to the individual or entity that wishes to use the Software. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo "Software" refers to the tool(s), script(s) and/or software product(s) (and any applicable documentation) provided with these terms to You by Oracle and which You wish to access and use to measure, monitor and/or manage Your usage of separately-licensed Oracle software (the "Programs") that has been licensed under a separate agreement between Oracle and You, such as an Oracle Master Agreement, an Oracle Software License and Services Agreement, an Oracle PartnerNetwork Agreement or an Oracle distribution agreement (each, an "Oracle License Agreement").  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Rights Granted>>"%TEMP%\ct_cpuq_tmp.txt"
echo Oracle grants You a non-exclusive, non-transferable limited right to use the Software, subject to the terms of this Agreement, for the limited purpose of measuring, monitoring and/or managing Your usage of the Programs.  You may allow Your agents and contractors (including, without limitation, outsourcers) to use the Software for this purpose and You are responsible for their compliance with this Agreement in such use.  You (including Your agents, contractors and/or outsourcers) may not use the Software for any other purpose.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Ownership and Restrictions>>"%TEMP%\ct_cpuq_tmp.txt"
echo Oracle and Oracle's licensors retain all ownership and intellectual property rights to the Software. The Software may be installed on one or more servers; provided, however, that You may only make one copy of the Software for backup or archival purposes.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Third party technology that may be appropriate or necessary for use with the Software is specified in the Software documentation, notice files or readme files.  Such third party technology is licensed to You under the terms of the third party technology license agreement specified >>"%TEMP%\ct_cpuq_tmp.txt"in the Software documentation, notice files or readme files and not under the terms of this Agreement.  
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo You may not:>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	use the Software for Your own internal data processing or for any commercial or production purposes, or use the Software for any purpose except the purpose stated herein; >>"%TEMP%\ct_cpuq_tmp.txt"
echo -	remove or modify any Software markings or any notice of Oracle's or Oracle's licensors' proprietary rights;>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	make the Software available in any manner to any third party for use in the third party's business operations, without Oracle's prior written consent;>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	use the Software to provide third party training or rent or lease the Software or use the Software for commercial time sharing or service bureau use;>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	assign this Agreement or give or transfer the Software or an interest in them to another individual or entity;>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	cause or permit reverse engineering (unless required by law for interoperability), disassembly or decompilation of the Software (the foregoing prohibition includes but is not limited to review of data structures or similar materials produced by the Software);>>"%TEMP%\ct_cpuq_tmp.txt"
echo -	disclose results of any Software benchmark tests without Oracle's prior written consent; >>"%TEMP%\ct_cpuq_tmp.txt"
echo -	use any Oracle name, trademark or logo without Oracle's prior written consent.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Disclaimer of Warranty>>"%TEMP%\ct_cpuq_tmp.txt"
echo ORACLE DOES NOT GUARANTEE THAT THE SOFTWARE WILL PERFORM ERROR-FREE OR UNINTERRUPTED.   TO THE EXTENT NOT PROHIBITED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND AND THERE ARE NO WARRANTIES, EXPRESS OR IMPLIED, OR CONDITIONS, INCLUDING WITHOUT LIMITATION, WARRANTIES OR CONDITIONS OF MERCHANTABILITY, NONINFRINGEMENT OR FITNESS FOR A PARTICULAR PURPOSE, THAT APPLY TO THE SOFTWARE.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo No Right to Technical Support>>"%TEMP%\ct_cpuq_tmp.txt"
echo You acknowledge and agree that Oracle's technical support organization will not provide You with technical support for the Software licensed under this Agreement.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo End of Agreement>>"%TEMP%\ct_cpuq_tmp.txt"
echo You may terminate this Agreement by destroying all copies of the Software.  Oracle has the right to terminate Your right to use the Software at any time upon notice to You, in which case You shall destroy all copies of the Software. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Entire Agreement>>"%TEMP%\ct_cpuq_tmp.txt"
echo You agree that this Agreement is the complete agreement for the Software and supersedes all prior or contemporaneous agreements or representations, written or oral, regarding the Software.  If any term of this Agreement is found to be invalid or unenforceable, the remaining provisions will remain effective and such term shall be replaced with a term consistent with the purpose and intent of this Agreement. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Limitation of Liability>>"%TEMP%\ct_cpuq_tmp.txt"
echo IN NO EVENT SHALL ORACLE BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF PROFITS, REVENUE, DATA OR DATA USE, INCURRED BY YOU OR ANY THIRD PARTY.  ORACLE'S ENTIRE LIABILITY FOR DAMAGES ARISING OUT OF OR RELATED TO THIS AGREEMENT, WHETHER IN CONTRACT OR TORT OR OTHERWISE, SHALL IN NO EVENT EXCEED THE GREATER OF ONE THOUSAND U.S. DOLLARS (U.S. $1,000) OR THE LICENSE FEES THAT YOU HAVE PAID TO ORACLE FOR PROGRAMS PURSUANT TO AN ORACLE LICENSE AGREEMENT.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Export>>"%TEMP%\ct_cpuq_tmp.txt"
echo Export laws and regulations of the United States and any other relevant local export laws and regulations apply to the Software.  You agree that such export control laws govern Your use of the Software (including technical data) provided under this Agreement, and You agree to comply with all such export laws and regulations (including "deemed export" and "deemed re-export" regulations).  You agree that no data, information, and/or Software (or direct product thereof) will be exported, directly or indirectly, in violation of any export laws, nor will they be used for any purpose prohibited by these laws including, without limitation, nuclear, chemical, or biological weapons proliferation, or development of missile technology.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Other>>"%TEMP%\ct_cpuq_tmp.txt"
echo 1.	This Agreement is governed by the substantive and procedural laws of the State of California, USA.  You and Oracle agree to submit to the exclusive jurisdiction of, and venue in, the courts of San Francisco or Santa Clara counties in California in any dispute arising out of or relating to this Agreement. >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 2.	You may not assign this Agreement or give or transfer the Software or an interest in them to another individual or entity.  If You grant a security interest in the Software, the secured party has no right to use or transfer the Software.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 3.	Except for actions for breach of Oracle's proprietary rights, no action, regardless of form, arising out of or relating to this Agreement may be brought by either party more than two years after the cause of action has accrued.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 4.	The relationship between You and Oracle is that of licensee/licensor.  Nothing in this Agreement shall be construed to create a partnership, joint venture, agency, or employment relationship between the parties.  The parties agree that they are acting solely as independent contractors hereunder and agree that the parties have no fiduciary duty to one another or any other special or implied duties that are not expressly stated herein.  Neither party has any authority to act as agent for, or to incur any obligations on behalf of or in the name of the other.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 5.	This Agreement may not be modified and the rights and restrictions may not be altered or waived except in a writing signed by authorized representatives of You and Oracle.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 6.	Any notice required under this Agreement shall be provided to the other party in writing.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 7.	In order to assist You with the measurement, monitoring or management of Your usage of the Programs, Oracle may have access to and collect Your information, which may include personal information, and data residing on Oracle, customer or third-party systems on which the Software is used and/or to which Oracle is provided access to perform any associated services.  Oracle treats such information and data in accordance with the terms of the Oracle Services Privacy Policy and the Oracle Corporate Security Practices, which are available at http://www.oracle.com/contracts, and treats such data as confidential in accordance with the terms of the Oracle License Agreement applicable to the Programs.  The Oracle Services Privacy Policy and the Oracle Corporate Security Practices are subject to change at Oracle's discretion; however, Oracle will not materially reduce the level of protection specified in the Oracle Services Privacy Policy or the Oracle Corporate Security Practices in effect at the time the information was collected during the period that Oracle retains such information.  >>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Contact Information>>"%TEMP%\ct_cpuq_tmp.txt"
echo Should You have any questions concerning Your use of the Software or this Agreement, please contact Oracle at: http://www.oracle.com/corporate/contact/>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Oracle America, Inc.>>"%TEMP%\ct_cpuq_tmp.txt"
echo 500 Oracle Parkway, >>"%TEMP%\ct_cpuq_tmp.txt"
echo Redwood City, CA 94065>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo.>>"%TEMP%\ct_cpuq_tmp.txt"
echo Last updated 1 November 2018>>"%TEMP%\ct_cpuq_tmp.txt"

more "%TEMP%\ct_cpuq_tmp.txt"

:promptloop
set /p ANSWER=Accept License Agreement? (y\n\q)

if "%ANSWER%" == "y" (
       goto main
) else if "%ANSWER%" == "n" (
       goto licagreement
) else if "%ANSWER%" == "q" (
       goto licagreement
) else (
	goto promptloop
)

:licagreement
echo.
echo You cannot run this program without agreeing to the license agreement.
goto ct_cpu_info



:main
::
:: setup temp files to hold data
::
  rem set MACHINE_NAME=%COMPUTERNAME%
  rem set MACHINE_MSINFO=%1\%MACHINE_NAME%-MSinfo.txt
    
    set RETURN_FILE=%COMPUTERNAME%-ct_cpuq.txt
	if exist "%*" (
	    set TEMP=%*
		set RETURN_FILE="%*\%COMPUTERNAME%-ct_cpuq.txt"
	)
	
	del "%TEMP%\ct_cpuq_tmp.txt"

:: Get windows Version numbers
  For /f "tokens=2 delims=[]" %%G in ('ver') Do (set _version=%%G) 
  For /f "tokens=2,3,4 delims=. " %%G in ('echo %_version%') Do (set _major=%%G& set _minor=%%H& set _build=%%I) 
	
::
:: Gather OS, CPU, IP Address and machine name information
::  populate IP adresses to file
::

  echo Gathering machine information ....
  echo ct_cpuq.cmd v.19.1               > %RETURN_FILE%
  echo CT Version %CT_BUILD_VERSION%    >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%
  echo Script Start Date: %date%        >> %RETURN_FILE%
  echo Script Start Time: %time%        >> %RETURN_FILE%
  if "%_major%"=="5" (
	:: Since catlist only supported on < Server 2008 and Windows, don't use it on those platforms.
	  "%ProgramFiles%\Common Files\Microsoft Shared\MSInfo\msinfo32.exe" /report "%TEMP%\ct_cpuq_tmp.txt" /categories catlist
	  echo "%ProgramFiles%\Common Files\Microsoft Shared\MSInfo\msinfo32.exe" /report "%TEMP%\ct_cpuq_tmp.txt" /categories catlist >> %RETURN_FILE%
	  echo ################################ >> %RETURN_FILE%
	  type "%TEMP%\ct_cpuq_tmp.txt"          >> %RETURN_FILE%
	 
	 %SystemRoot%\regedit /E "%TEMP%\ct_cpuq_tmp.txt" "HKEY_LOCAL_MACHINE\Hardware\Description\System\CentralProcessor"
	 echo ################################ >> %RETURN_FILE%
     echo regedit /E "%TEMP%\ct_cpuq_tmp.txt" "HKEY_LOCAL_MACHINE\Hardware\Description\System\CentralProcessor" >> %RETURN_FILE%
  ) else (
  	  echo "msinfo32.exe catlist option not run on Windows 2008, Windows Vista or greater." >> %RETURN_FILE%
	  echo ################################ >> %RETURN_FILE%
	 
	 %SystemRoot%\System32\reg export HKLM\Hardware\Description\System\CentralProcessor "%TEMP%\ct_cpuq_tmp.txt"
	 echo ################################ >> %RETURN_FILE%
     echo reg export HKLM\Hardware\Description\System\CentralProcessor "%TEMP%\ct_cpuq_tmp.txt" >> %RETURN_FILE%
  )
  

  echo ################################ >> %RETURN_FILE%
  type "%TEMP%\ct_cpuq_tmp.txt"         >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%


  :: Preparing VB Script file
  :: Escaping with ^ all command characters & < > | ON OFF
  echo.' Set output file                                                                                                                                                      > "%TEMP%\ct_cpuq_tmp.vbs"
  echo.On Error Resume Next                                                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.Set objFSO = CreateObject("Scripting.FileSystemObject")                                                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.Set objTextFile = objFSO.CreateTextFile("%TEMP%\ct_cpuq_tmp.txt")                                                                                                     >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.' Connect to Local Machine and get data.                                                                                                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.' If cannot connect to Local Machine print message.                                                                                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.strComputer = "."                                                                                                                                                     >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.Set objWMIService = GetObject("winmgmts:" _                                                                                                                           >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo. ^& "{impersonationLevel=impersonate}!\\" ^& strComputer ^& "\root\cimv2")                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.If objWMIService Is Nothing Then                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  objTextFile.WriteLine("Unable to bind to WMI!")                                                                                                                     >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.Else                                                                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get Operating System information                                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set colOSes = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")                                                                                        >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each objOS in colOSes                                                                                                                                           >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("Operating System")                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  Caption: " ^& objOS.Caption)                                                                                                             >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  Version: " ^& objOS.Version)                                                                                                             >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("Computer Name: " ^& objOS.CSName)                                                                                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get DNS Domain                                                                                                                                                    >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set colDNSs = objWMIService.ExecQuery ("Select DNSDomain from Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each objDNS in colDNSs                                                                                                                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    If Not IsNull(objDNS.DNSDomain) Then                                                                                                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("DNS Domain: " ^& objDNS.DNSDomain)                                                                                                       >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    End If                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  objTextFile.WriteLine("System")                                                                                                                                     >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get UUID                                                                                                                                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set colUUID = objWMIService.ExecQuery("select uuid from Win32_ComputerSystemProduct")                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each objUUID in colUUID                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    If Not IsNull(objUUID.UUID) Then                                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("UUID=" ^& objUUID.UUID)                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    End If                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get System Machine information.                                                                                                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Check if script is running on a virtual machine                                                                                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set colCompSys = objWMIService.ExecQuery("Select * from Win32_ComputerSystem")                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each objCS in colCompSys                                                                                                                                        >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    If InStr(objCS.Manufacturer, "VMware") ^> 0 Then                                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  VIRTUAL MACHINE RUNNING: " ^& objCS.Manufacturer)                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      isVirtualMachine = True                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    ElseIf InStr(objCS.Manufacturer, "Xen") ^> 0 Then                                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  VIRTUAL MACHINE RUNNING: " ^& objCS.Manufacturer)                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      isVirtualMachine = True                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    ElseIf InStr(objCS.Manufacturer, "Red Hat") ^> 0 Then                                                                                                             >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  VIRTUAL MACHINE RUNNING: " ^& objCS.Manufacturer)                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      isVirtualMachine = True                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    ElseIf InStr(objCS.Manufacturer, "Microsoft Corporation") ^> 0 Then                                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  VIRTUAL MACHINE RUNNING: " ^& objCS.Manufacturer)                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  If this is a Hyper-V Virtualized environment " )                                                                                       >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  please run ct_cpuq.cmd in the Root Partition" )                                                                                       >> "%TEMP%\ct_cpuq_tmp.vbs"  
  echo.      isVirtualMachine = True                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    ElseIf InStr(objCS.Model, "VirtualBox") ^> 0 Then                                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("  VIRTUAL MACHINE RUNNING: " ^& objCS.Model)                                                                                             >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      isVirtualMachine = True                                                                                                                                         >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    End If                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    If isVirtualMachine = True Then                                                                                                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteBlankLines(1)                                                                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteLine "** NOTICE:  VIRTUAL MACHINE RUNNING: " ^& objCS.Manufacturer ^& " " ^& objCS.Model                                                    >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteLine "** Please provide Oracle with information about the hardware configuration "                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteLine "** of the physical server which is hosting this Virtual Machine "                                                                     >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteLine "** If applicable, please run the script on the host operating system "                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteLine "** Thank You."                                                                                                                        >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      objTextFile.WriteLine("CPUQ: CT-01104: WARNING: "  ^& objCS.Manufacturer ^& " " ^& objCS.Model ^& " virtual machine, processor information is also needed for the physical machine") >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Wscript.StdOut.WriteBlankLines(1)                                                                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      If InStr(objCS.Manufacturer, "Microsoft Corporation") ^> 0 Then                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.        Wscript.StdOut.WriteLine "  If this is a Hyper-V Virtualized environment "                                                                                    >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.        Wscript.StdOut.WriteLine "  please run ct_cpuq.cmd in the Root Partition"                                                                                    >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      End If                                                                                                                                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    End If                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  Manufacturer: " ^& objCS.Manufacturer)                                                                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  Model: " ^& objCS.Model)                                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  NumberOfProcessors: " ^& objCS.NumberOfProcessors)                                                                                       >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  objTextFile.WriteLine("Processors")                                                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get CPU information                                                                                                                                               >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set colProcessors = objWMIService.ExecQuery("Select * from Win32_Processor")                                                                                        >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each objProcessor in colProcessors                                                                                                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU Name: " ^& objProcessor.Name)                                                                                                        >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU Description: " ^& objProcessor.Description)                                                                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU MaximumClockSpeed [MHz]: " ^& objProcessor.MaxClockSpeed)                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU NumberOfCores: " ^& objProcessor.NumberOfCores)                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU NumberOfLogicalProcessors: " ^& objProcessor.NumberOfLogicalProcessors)                                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' NumberOfCores and NumberOfLogicalProcessors are only supported in the latest WMI version (available as a hotfix)                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  If Err.Number = 438 Then                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU NumberOfCores: PATCH NOT AVAILABLE (Error Number: " ^& Err.Number ^& "; Error Description: " ^& Err.Description ^& ")")              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    objTextFile.WriteLine("  CPU NumberOfLogicalProcessors: PATCH NOT AVAILABLE (Error Number: " ^& Err.Number ^& "; Error Description: " ^& Err.Description ^& ")")  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  End If                                                                                                                                                              >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  objTextFile.WriteLine("IP Address")                                                                                                                                 >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.                                                                                                                                                                      >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  ' Get IP Address(es)                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Set IPConfigSet = objWMIService.ExecQuery ("Select IPAddress from Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")                                          >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  For Each IPConfig in IPConfigSet                                                                                                                                    >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    If Not IsNull(IPConfig.IPAddress) Then                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      For i=LBound(IPConfig.IPAddress) to UBound(IPConfig.IPAddress)                                                                                                  >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      If IPConfig.IPAddress(i) ^<^> "0.0.0.0" Then objTextFile.WriteLine("  IP Address: " ^& IPConfig.IPAddress(i))                                                   >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.      Next                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.    End If                                                                                                                                                            >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.  Next                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"
  echo.End if                                                                                                                                                                >> "%TEMP%\ct_cpuq_tmp.vbs"

  echo Preparing to run VB Script file "%TEMP%\ct_cpuq_tmp.vbs": >> %RETURN_FILE%
  echo to query Windows Management Instrumentation (WMI) >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%
  type "%TEMP%\ct_cpuq_tmp.vbs"          >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%

       %SystemRoot%\System32\cscript.exe "%TEMP%\ct_cpuq_tmp.vbs" 2> "%TEMP%\cpu_info.err"
  echo %SystemRoot%\System32\cscript.exe "%TEMP%\ct_cpuq_tmp.vbs" 2^> "%TEMP%\cpu_info.err"  >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%
  type "%TEMP%\ct_cpuq_tmp.txt"          >> %RETURN_FILE%
  type "%TEMP%\cpu_info.err"              >> %RETURN_FILE%
 
  del "%TEMP%\ct_cpuq_tmp.txt"
  del "%TEMP%\cpu_info.err"
  del "%TEMP%\ct_cpuq_tmp.vbs"
    
  echo Script End Time: %time%          >> %RETURN_FILE%
  echo ################################ >> %RETURN_FILE%

if not exist "%*" (
	echo Done.
	echo Please collect the output file: %RETURN_FILE%
)

  goto ct_cpu_info


:ct_cpu_info
endlocal
echo.
:EOF
