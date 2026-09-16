rule Virus_Hijack_Trojan_GenericKDZ_98113_315_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_315_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd086c246b8b0701ff91f723cbce5977df31fec543a99d0076588f526df50bd"

  strings:
    $s1 = ">O{<ScaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}