import "pe"
rule _Trojan_Hooker__Win32_Floxif_A_1_Virus_Autorun_Gen_Trojan_Keylog_138 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker _Win32.Floxif.A_1.vir, Virus.Autorun_Gen.Trojan.Keylogger.7H3@aaCHNQcj.vir, Virus.Autorun_Gen.Trojan.Keylogger.9H3@aaCHNQcj.vir, Virus.Hijack_Gen.Trojan.Keylogger.8K3@aWCMkAkj.vir, Virus.Hijack_Gen.Trojan.Keylogger.@H3@aaCHNQcj.vir, Virus.Hijack_Gen.Trojan.Keylogger.@H3@aaCHNQcj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f598c7c302b8a35e2bfb44e58b6c9fbd1574e474acaa6d3651238049a5a9aba4"
    hash2       = "cf3b677883305b64237c15ca0fd9a9f4b1066fc100e229921408dafbe17c43cf"
    hash3       = "074db2ce466086c9a3ef4a588d385304c2c1719c712b44250382c1d016feb59e"
    hash4       = "f0f80c13953afb7e5f71fd340f9602e3094ce43579fb1777888d4c6f7d13fac1"
    hash5       = "e3965333f4c20a9e7cb015d5fe41f45cae28020f9844eb197e6cc3f39f44622d"
    hash6       = "7c52f9841f937424577d2c45e2fc8ec3a9f263f70568b50494124de57b451d98"

  strings:
    $s1  = "Program Files\\Internet Explorer\\iexplore.exe" fullword ascii
    $s2  = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" fullword ascii
    $s3  = "@Facets and Enumeration not allowed on this kind of datatype \"%s\"Invalid built-in type name \"%s\"*1999 XML Schema Translator" wide
    $s4  = "[Stoping]" fullword ascii
    $s5  = "Windows 08_R2(Server)" fullword ascii
    $s6  = "Windows 12_R2(Server)" fullword ascii
    $s7  = "Windows 12(Server)" fullword ascii
    $s8  = "Windows 08(Server)" fullword ascii
    $s9  = "Windows 03(Server)" fullword ascii
    $s10 = "(Server)" fullword ascii
    $s11 = "[Print S~creen]" fullword wide
    $s12 = "[Sc~roll Lock]" fullword wide
    $s13 = "[Nu~m Lock]" fullword wide
    $s14 = "[~Num Lock]" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "4cca3a40d43897162b45e7061f7a7c4e" and (8 of them)
    ) or (all of them)
}