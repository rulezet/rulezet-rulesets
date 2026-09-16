rule Virus_Hijack_Trojan_GenericKDZ_94849_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ead6fa1b99a0dfb0b07c7ea3ad470d6eeda55ed627abe802d5a578310af1b247"

  strings:
    $s1 = "haRt%g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}