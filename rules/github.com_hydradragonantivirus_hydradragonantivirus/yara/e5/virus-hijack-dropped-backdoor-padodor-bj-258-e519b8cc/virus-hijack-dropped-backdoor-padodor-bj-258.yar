rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_258 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_258.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7968f1e3227a460c13457ef4838b53e2ff190b6ee745a626c83ab18afffa4978"

  strings:
    $s1 = "RiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}