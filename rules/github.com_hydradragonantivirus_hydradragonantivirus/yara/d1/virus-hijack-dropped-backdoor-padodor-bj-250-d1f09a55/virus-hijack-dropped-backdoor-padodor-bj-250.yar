rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_250 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_250.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1116f2e909801beb0bfc6f13090a5b86ff2b26fd8eee5c3fcb05f0e251f13cd8"

  strings:
    $s1 = "UiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}