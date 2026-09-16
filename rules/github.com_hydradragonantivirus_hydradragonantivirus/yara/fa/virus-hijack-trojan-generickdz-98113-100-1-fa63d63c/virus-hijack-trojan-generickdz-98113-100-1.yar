rule Virus_Hijack_Trojan_GenericKDZ_98113_100_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_100_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4bd45770fb4b5c5d4873b8e7dc4d2334f407da9f9853a012624515a4f50ef10"

  strings:
    $s1 = "a>VInE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}