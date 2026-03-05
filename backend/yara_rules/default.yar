/*
 * FCTT Default YARA Rules
 * Place additional .yar files in this directory to extend detection.
 */

rule Mimikatz_Gen {
    meta:
        description = "Detects Mimikatz credential dumper"
        author = "FCTT"
        severity = "CRITICAL"
        reference = "T1003"
    strings:
        $s1 = "mimikatz" nocase wide ascii
        $s2 = "sekurlsa" nocase
        $s3 = "privilege::debug" nocase
        $s4 = "lsadump" nocase
    condition:
        any of them
}

rule Encoded_PowerShell_Execution {
    meta:
        description = "Detects encoded PowerShell execution"
        author = "FCTT"
        severity = "HIGH"
        reference = "T1086"
    strings:
        $enc = "powershell" nocase
        $flag = "-enc" nocase
        $b64 = /[A-Za-z0-9+\/]{50,}/ wide ascii
    condition:
        all of them
}

rule Metasploit_Stager_Rev_TCP {
    meta:
        description = "Metasploit reverse TCP stager shellcode"
        author = "FCTT"
        severity = "CRITICAL"
        reference = "T1055"
    strings:
        $msfstager = { fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 }
    condition:
        $msfstager
}

rule Suspicious_PE_In_RWX_Memory {
    meta:
        description = "PE header found in executable writable memory"
        author = "FCTT"
        severity = "HIGH"
        reference = "T1055"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule APT_C2_Beacon_Pattern {
    meta:
        description = "Generic C2 beacon pattern detection"
        author = "FCTT"
        severity = "HIGH"
        reference = "T1071"
    strings:
        $ua1 = "Mozilla/5.0" nocase
        $ua2 = "Windows NT" nocase
        $b64 = /[A-Za-z0-9+\/]{100,}=*/
    condition:
        all of them
}

rule Credential_Dumping_Tool {
    meta:
        description = "Generic credential dumping tool indicator"
        author = "FCTT"
        severity = "CRITICAL"
        reference = "T1003"
    strings:
        $s1 = "lsass" nocase
        $s2 = "SAM" fullword
        $s3 = "NTLM" fullword
        $s4 = "wce" nocase fullword
        $s5 = "pwdump" nocase
    condition:
        2 of them
}

rule Suspicious_Registry_Persistence {
    meta:
        description = "Registry-based persistence mechanism"
        author = "FCTT"
        severity = "MEDIUM"
        reference = "T1547"
    strings:
        $r1 = "\\CurrentVersion\\Run" nocase
        $r2 = "\\CurrentVersion\\RunOnce" nocase
        $r3 = "\\Winlogon" nocase
    condition:
        any of them
}
