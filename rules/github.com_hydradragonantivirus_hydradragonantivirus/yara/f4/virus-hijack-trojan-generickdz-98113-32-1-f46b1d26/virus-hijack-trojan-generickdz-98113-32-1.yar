rule Virus_Hijack_Trojan_GenericKDZ_98113_32_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b99fdcee2d80d8b1b090f1d9b12e653cdb645f5a1dbd549d5df76b1242b88d"

  strings:
    $s1 = "pEsA!X" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}