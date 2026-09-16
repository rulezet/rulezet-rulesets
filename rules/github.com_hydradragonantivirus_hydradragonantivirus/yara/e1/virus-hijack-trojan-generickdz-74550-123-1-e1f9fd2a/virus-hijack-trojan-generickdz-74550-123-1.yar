rule Virus_Hijack_Trojan_GenericKDZ_74550_123_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2a2cd040d1013a54e6170cb51024e7059322496166bd93c187b2f7c9332e167"

  strings:
    $s1 = "AWay):Z" fullword ascii
    $s2 = "?46\"sOAm$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}