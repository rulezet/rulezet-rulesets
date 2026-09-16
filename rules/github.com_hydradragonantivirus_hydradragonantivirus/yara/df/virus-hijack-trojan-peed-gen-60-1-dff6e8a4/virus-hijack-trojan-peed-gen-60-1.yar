rule Virus_Hijack_Trojan_Peed_Gen_60_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c32df58ab8c1b5f4d9772358b3c44c82f6c4e8282d3459cf298b64b5cf2e1698"

  strings:
    $s1 = "u%lEEP" fullword ascii
    $s2 = "pAtu+E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}