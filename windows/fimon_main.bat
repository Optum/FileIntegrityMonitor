@REM Description : File Integrity Monitor for Windows Servers.
@REM Description : This main file is to be called by Task Scheduler to run the provided ps1 script and json file.
@REM Created     : 10/2022
@REM Modified    : 11/2023
@REM Contact     : 
@REM Keywords    : Monitor , Monitoring , Integrity, Audit
@ECHO OFF

FOR /F %%A IN ('WMIC OS GET LocalDateTime ^| FIND "."') DO SET DT=%%A
SET DateTime=%DT:~0,8%_%DT:~8,4%

@REM Command
PowerShell -File ".\fimon.ps1" -DateTime %DateTime% > ".\fimon.out"
PowerShell -File ".\fimon.ps1" -DateTime %DateTime% -OutFile ".\fimon.out"