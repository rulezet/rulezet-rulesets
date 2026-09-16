rule Virus_Hijack_Trojan_GenericKDZ_74550_255_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_255_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d5841d0bab97ea2a6a82e96eb74d4780f7fcfb040c0d97f033694ffeda96c1"

  strings:
    $s1 = "**MINk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}