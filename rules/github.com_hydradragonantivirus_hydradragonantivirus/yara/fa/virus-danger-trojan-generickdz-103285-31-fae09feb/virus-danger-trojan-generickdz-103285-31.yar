rule Virus_Danger_Trojan_GenericKDZ_103285_31 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de8cbf78c4e95fd8f8a1799197d6e14d9a3cda9f5a7442f6efb914c582a8ce23"

  strings:
    $s1 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}