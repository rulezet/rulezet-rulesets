rule Virus_Hijack_Trojan_GenericKDZ_74550_389_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36b252df1a92bf39c17d3ec96a320e597fd53512009fc1b71811f4e9bb1c1782"

  strings:
    $s1 = "rOKA,Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}