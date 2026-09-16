rule Virus_Hijack_Trojan_GenericKDZ_74550_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb5a43b1aa1f97fae6778907ab4d73f37be26612c6247f10557e7c1b6fad444b"

  strings:
    $s1 = "$AFfA*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}