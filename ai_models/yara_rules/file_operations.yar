
rule Mass_File_Operations
{
    meta:
        description = "Detects potential mass file operations (ransomware behavior)"
        author = "Fixion"
        category = "file_operations"

    strings:
        $op1 = "FindFirstFile"
        $op2 = "FindNextFile"
        $op3 = "CryptEncrypt"
        $op4 = "CryptDecrypt"
        $op5 = "CreateFile"
        $op6 = "WriteFile"
        $op7 = "DeleteFile"

    condition:
        uint16(0) == 0x5A4D and 4 of ($op*)
}

rule Anti_Analysis_Techniques
{
    meta:
        description = "Detects anti-analysis techniques"
        author = "Fixion"
        category = "anti_analysis"

    strings:
        $aa1 = "IsDebuggerPresent"
        $aa2 = "CheckRemoteDebuggerPresent"
        $aa3 = "OutputDebugString"
        $aa4 = "GetTickCount"
        $aa5 = "Sleep"
        $aa6 = "VirtualProtect"

    condition:
        uint16(0) == 0x5A4D and 3 of ($aa*)
}
