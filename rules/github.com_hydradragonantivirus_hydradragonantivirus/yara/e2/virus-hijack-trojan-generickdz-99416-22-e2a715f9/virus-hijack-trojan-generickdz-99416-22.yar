rule Virus_Hijack_Trojan_GenericKDZ_99416_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4764e29196f059781cc1fbf71a967010c60536e1ce15a6f037357eeabb0d2cf6"

  strings:
    $s1 = ";'User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}