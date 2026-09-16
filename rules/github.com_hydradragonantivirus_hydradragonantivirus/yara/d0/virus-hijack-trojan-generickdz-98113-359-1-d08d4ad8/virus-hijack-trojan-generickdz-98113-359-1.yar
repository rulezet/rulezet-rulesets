rule Virus_Hijack_Trojan_GenericKDZ_98113_359_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_359_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a21ad64da325f602de55c35f68d55a0029459148d7296ea59ee0dd0a11e91c6"

  strings:
    $s1 = "hYKE%," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}