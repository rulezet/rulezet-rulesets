rule Virus_Hijack_Trojan_GenericKDZ_79663_108 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_108.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5a6c3b1da9e5ad9b1cd3ca6765ff9f41846171e9fdc9d1321df06273edfbff9"

  strings:
    $s1 = "Othis notice will include a copy of your agreemen" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}