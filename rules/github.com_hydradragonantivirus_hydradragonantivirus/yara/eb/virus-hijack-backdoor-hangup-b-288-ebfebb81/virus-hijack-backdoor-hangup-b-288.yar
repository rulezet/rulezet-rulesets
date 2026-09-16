rule Virus_Hijack_Backdoor_Hangup_B_288 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_288.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c817bde4f50bd95c1aff36f0539ecc580075c425fc47e0b96759dfd94b668888"

  strings:
    $s1 = "tuw{coSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}