rule Virus_Hijack_Trojan_GenericKDZ_98388_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffcf4a14e03bd41235a5eb611322e8c3eca4b7448a99a15983fe45408a277377"

  strings:
    $s1 = "Q!RAke!" fullword ascii
    $s2 = "gant)~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}