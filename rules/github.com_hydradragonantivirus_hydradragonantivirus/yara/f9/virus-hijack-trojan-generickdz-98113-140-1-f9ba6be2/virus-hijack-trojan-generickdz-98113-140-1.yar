rule Virus_Hijack_Trojan_GenericKDZ_98113_140_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38030d2efccba528b3ac66a2da9ab485d9582d84678d86ee5c4317822d625149"

  strings:
    $s1 = "KOaE#Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}