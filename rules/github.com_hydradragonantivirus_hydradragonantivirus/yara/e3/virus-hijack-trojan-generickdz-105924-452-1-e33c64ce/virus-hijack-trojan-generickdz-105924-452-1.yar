rule Virus_Hijack_Trojan_GenericKDZ_105924_452_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_452_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "954d2193e3a206f86c5debdbffc6623a6d77564b84b44a1d33ef96ae69a5a051"

  strings:
    $s1 = "/,shOw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}