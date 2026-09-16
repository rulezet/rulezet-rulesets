rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2836cf4eb1e7f3bf10d75d710a364829b25d30a9e071a83f0ea7a04381385d6f"

  strings:
    $s1 = "uiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}