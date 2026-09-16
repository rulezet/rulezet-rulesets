rule Virus_Hijack_Trojan_GenericKDZ_98113_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bec54ae1b7a7ec850404a70eb62d61029b14d2f295e1c153274083cdfb4f178"

  strings:
    $s1 = "WeeL}S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}