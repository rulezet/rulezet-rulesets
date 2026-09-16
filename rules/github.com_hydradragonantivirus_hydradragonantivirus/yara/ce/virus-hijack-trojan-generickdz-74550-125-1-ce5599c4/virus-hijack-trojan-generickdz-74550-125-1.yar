rule Virus_Hijack_Trojan_GenericKDZ_74550_125_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_125_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edcee7cd9406e4cba69e43d4f6cfc88d851f74495c3df747e48a693cdd094da3"

  strings:
    $s1 = "*&aWnY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}