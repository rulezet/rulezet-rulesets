rule Trojan_Danger_Trojan_GenericKD_72853156_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ba7948be1335bb3a105993138fdafc1dfdb3d7aa4c316ec35f2b0ddb40a3895"

  strings:
    $s1 = "Copyright 2014 AiosfdHuisfe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}