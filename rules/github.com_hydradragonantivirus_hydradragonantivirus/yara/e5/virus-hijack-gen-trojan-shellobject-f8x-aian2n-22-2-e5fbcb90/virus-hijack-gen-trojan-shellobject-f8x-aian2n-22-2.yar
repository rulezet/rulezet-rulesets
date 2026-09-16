rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_22_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b30c66787a2bea150a20083cefbd2530d7339d6bf21f29f360841110850158b"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;" fullword wide
    $s2 = "EyC:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\CHARTWIZ.oca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}