
rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Fixion"
        category = "script"

    strings:
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "DownloadString" nocase
        $ps3 = "DownloadFile" nocase
        $ps4 = "FromBase64String" nocase
        $ps5 = "EncodedCommand" nocase
        $ps6 = "WebClient" nocase
        $ps7 = "Start-Process" nocase

    condition:
        2 of ($ps*)
}

rule Suspicious_Batch_Commands
{
    meta:
        description = "Detects suspicious batch file commands"
        author = "Fixion"
        category = "script"

    strings:
        $cmd1 = "echo off"
        $cmd2 = "del /f /q"
        $cmd3 = "shutdown"
        $cmd4 = "taskkill"
        $cmd5 = "reg add"
        $cmd6 = "schtasks"
        $cmd7 = "netsh"

    condition:
        3 of ($cmd*)
}

rule VBA_Macro_Suspicious
{
    meta:
        description = "Detects suspicious VBA macro content"
        author = "Fixion"
        category = "macro"

    strings:
        $vba1 = "Auto_Open"
        $vba2 = "Document_Open"
        $vba3 = "Shell"
        $vba4 = "CreateObject"
        $vba5 = "WScript.Shell"
        $vba6 = "URLDownloadToFile"

    condition:
        2 of ($vba*)
}
