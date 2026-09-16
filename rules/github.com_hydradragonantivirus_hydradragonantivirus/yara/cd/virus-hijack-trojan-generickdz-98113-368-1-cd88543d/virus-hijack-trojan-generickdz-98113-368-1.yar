rule Virus_Hijack_Trojan_GenericKDZ_98113_368_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_368_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8409ca7bdf1c0501222a44d7ed332a9b904eafb3633d6e43a2e40c616f3bfa5e"

  strings:
    $s1 = "&TUth!%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}