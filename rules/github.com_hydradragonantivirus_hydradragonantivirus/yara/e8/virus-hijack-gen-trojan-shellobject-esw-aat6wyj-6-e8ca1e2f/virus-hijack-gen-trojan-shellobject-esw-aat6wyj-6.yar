rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cec3dd0a005a6d173b6ca20839ff9e7c9b8e9f5e3e98f66fb37b80cd175973d1"

  strings:
    $s1 = "Vrwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}