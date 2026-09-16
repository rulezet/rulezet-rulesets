rule Virus_Hijack_Trojan_GenericKDZ_79663_66_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38f4fb330b03b748f26289330342fb3630ccb8b1dcb693525c07f99d5ea384af"

  strings:
    $s1 = "+#sOjA" fullword ascii
    $s2 = "i$cleW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}