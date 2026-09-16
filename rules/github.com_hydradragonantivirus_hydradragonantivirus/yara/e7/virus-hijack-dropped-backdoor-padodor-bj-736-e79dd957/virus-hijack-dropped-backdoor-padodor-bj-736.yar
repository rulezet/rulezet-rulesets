rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_736 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_736.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27ce03a7370fceb86e814fbf4eb3f3ea7f87e860dea2f48d5cf99b0016ee1269"

  strings:
    $s1 = "wOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}