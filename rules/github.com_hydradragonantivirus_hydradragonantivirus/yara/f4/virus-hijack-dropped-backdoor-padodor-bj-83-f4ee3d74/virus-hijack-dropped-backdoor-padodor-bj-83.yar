rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_83 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89afbfad19f0d5a4200ede09bda0d5bbf4bddceda3a3c1635d3b413d51d25e1a"

  strings:
    $s1 = "%iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}