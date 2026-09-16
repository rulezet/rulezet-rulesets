rule Virus_Hijack_Trojan_Agent_DQQO_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb3d984ea12e2722df17f26540f8bd8ba7d4911eac7d83fc2419a3688e6f861d"

  strings:
    $s1 = "IEC 61966-2.1 Default RGB colour space " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}