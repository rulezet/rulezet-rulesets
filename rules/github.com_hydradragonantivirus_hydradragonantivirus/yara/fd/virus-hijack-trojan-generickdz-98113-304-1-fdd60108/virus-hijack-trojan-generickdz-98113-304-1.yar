rule Virus_Hijack_Trojan_GenericKDZ_98113_304_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_304_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4006b2970b5a09e5194c43e6f8b86f5158c4d671ee26f81398aba718d7e5dd7"

  strings:
    $s1 = "$!jIve" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}