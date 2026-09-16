rule Virus_Hijack_Trojan_GenericKDZ_74550_153_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82c0497293ccb8faf9dec561dfc32b80ecb744d036d787bf2edb88aeef912147"

  strings:
    $s1 = "tIfF>t!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}