rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7f9f75fc247faa8469adddfbe591559feeaa7a9cad1c9a39a2a83edd25c310"

  strings:
    $s1 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}