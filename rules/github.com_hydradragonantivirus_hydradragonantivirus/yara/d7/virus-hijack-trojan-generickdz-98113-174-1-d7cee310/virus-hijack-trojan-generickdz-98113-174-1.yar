rule Virus_Hijack_Trojan_GenericKDZ_98113_174_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a8b45bdb8c51517462b5c53c5f1496a99315a30e98702526f88367160eb9dca"

  strings:
    $s1 = "h Eral" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}