rule Virus_Hijack_Trojan_GenericKDZ_98113_152_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c289d56ab40c8643ff1a02dfd2a22ea0a86ac9a7e25d82f4ae08154d133d36f"

  strings:
    $s1 = "meak =" fullword ascii
    $s2 = "maki,e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}