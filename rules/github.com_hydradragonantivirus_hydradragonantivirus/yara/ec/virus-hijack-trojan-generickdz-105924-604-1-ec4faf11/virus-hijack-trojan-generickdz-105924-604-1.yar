rule Virus_Hijack_Trojan_GenericKDZ_105924_604_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_604_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eae773cc4d2eefd81e429d6c4d51f98a7b2b43b573047ca5eebf2553333847cb"

  strings:
    $s1 = "\\)hEnt;f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}