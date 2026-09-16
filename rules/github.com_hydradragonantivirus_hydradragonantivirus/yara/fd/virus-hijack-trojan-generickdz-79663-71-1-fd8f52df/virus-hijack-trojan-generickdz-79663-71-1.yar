rule Virus_Hijack_Trojan_GenericKDZ_79663_71_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e6c53cde03ce245821afdea39a1e804c032b8e48bca1685da75d8172de33c1"

  strings:
    $s1 = "QZM8(]datA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}