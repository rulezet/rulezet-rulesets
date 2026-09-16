rule Virus_Hijack_Trojan_GenericKDZ_94849_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d3c145568abd11f024405a38e62488e1c499d6b6e58615874fe320963e7ebd5"

  strings:
    $s1 = "#<wiTe" fullword ascii
    $s2 = "s%lEnT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}