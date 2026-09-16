rule Virus_Hijack_Trojan_GenericKDZ_98113_175_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_175_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09f68be4ca54cc1092bc2015a526c5cc9b0d2360fe117393fcf2da6f864620e6"

  strings:
    $s1 = "PoSs&F\"d" fullword ascii
    $s2 = "iy>RifF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}