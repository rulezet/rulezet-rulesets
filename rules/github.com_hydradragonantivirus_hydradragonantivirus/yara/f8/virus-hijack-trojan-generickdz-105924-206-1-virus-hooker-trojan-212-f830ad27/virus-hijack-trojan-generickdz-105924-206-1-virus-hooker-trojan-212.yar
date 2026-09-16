rule _Virus_Hijack_Trojan_GenericKDZ_105924_206_1_Virus_Hooker_Trojan_212 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_206_1.vir, Virus.Hooker_Trojan.GenericKD.48560802_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3aebdb374066a1250ef73bcde03e449e542f278d7d1d0f6c6b3b056619f2774"
    hash2       = "5dfbac5b2c733889241c86e6d799d146274d682c628df3cebcf84caabecf0687"

  strings:
    $s1 = "SYMCHK: PSAPI.DLL is available for download from" fullword ascii
    $s2 = "[SYMCHK] Not enough memory to read in \"%s\"." fullword ascii
    $s3 = "[SYMCHK] Seek on \"%s\" failed." fullword ascii
    $s4 = "[SYMCHK] Failed to open \"%s\"" fullword ascii
    $s5 = "no version" fullword ascii
    $s6 = "/s[epsu]  <SymbolPath>  Use <SymbolPath> as the search path." fullword ascii
    $s7 = "Unknown symbol path option '%c'" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}