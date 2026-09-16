rule Virus_Hijack_Trojan_GenericKDZ_79663_41_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25664571cdc37b8f143578fd97733cda57780d897b7a846f23295099b0c8e90b"

  strings:
    $s1 = "MelE!>=" fullword ascii
    $s2 = "z_\"PloP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}