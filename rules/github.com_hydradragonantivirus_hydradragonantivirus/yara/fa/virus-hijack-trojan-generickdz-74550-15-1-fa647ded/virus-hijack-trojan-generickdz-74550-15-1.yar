rule Virus_Hijack_Trojan_GenericKDZ_74550_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a68a5ca339147efa891b0476d89fb9942e82db7ea921f9cb6981000a49e1227"

  strings:
    $s1 = "ROsY@l" fullword ascii
    $s2 = "[(lOIn$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}