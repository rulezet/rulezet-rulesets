rule Virus_Hijack_Trojan_GenericKDZ_74550_267_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_267_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17f6d987d6ea77e8b8ec3538292923e923d0c5a461ca485e4cbdc1e6aab8cd0"

  strings:
    $s1 = "chirP?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}