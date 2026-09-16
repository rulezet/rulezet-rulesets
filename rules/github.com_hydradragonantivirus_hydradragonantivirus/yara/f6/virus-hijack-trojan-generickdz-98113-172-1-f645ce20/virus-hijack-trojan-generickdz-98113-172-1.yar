rule Virus_Hijack_Trojan_GenericKDZ_98113_172_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_172_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78caf466c25e3ccb9c61e53ec677049228b3734fec0f78e94ef8ff7f9c06b72"

  strings:
    $s1 = "YyF?VaRY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}