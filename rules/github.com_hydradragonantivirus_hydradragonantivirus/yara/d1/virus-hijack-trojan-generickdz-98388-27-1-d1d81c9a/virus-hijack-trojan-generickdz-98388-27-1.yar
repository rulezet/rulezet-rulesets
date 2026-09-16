rule Virus_Hijack_Trojan_GenericKDZ_98388_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6622fe643d936214f05fd7f288bdbf36f5d8c1dd0e81d8cb5c3419ddf1f1214e"

  strings:
    $s1 = "FrIz!x." fullword ascii
    $s2 = "5G=?ADze" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}