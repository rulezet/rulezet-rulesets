rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_767 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_767.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "545ce906c9596911bc8b39d2d685500dec5977ac34a31b3bed97af3e4be26887"

  strings:
    $s1 = "'and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}