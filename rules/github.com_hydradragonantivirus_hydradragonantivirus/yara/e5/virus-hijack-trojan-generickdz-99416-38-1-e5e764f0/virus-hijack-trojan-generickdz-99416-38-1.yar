rule Virus_Hijack_Trojan_GenericKDZ_99416_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf1dab048975e45b1683e899bda059d3b2c7ea53ce8c8d091b4358fd246b06c8"

  strings:
    $s1 = ",keEK .n" fullword ascii
    $s2 = "bEAd:X" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}