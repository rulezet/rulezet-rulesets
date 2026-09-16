rule Virus_Hijack_Trojan_GenericKDZ_98113_399_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_399_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36d8a826df18bf8a8ac09681142869c353310fe008598e9b7d1f88283895292c"

  strings:
    $s1 = "tODE,h" fullword ascii
    $s2 = "angO&x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}