rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_673 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_673.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5a004622bd4d1f3c6d03b312a51120a3d9da1dcd071efa7bd42c343081a6ff2"

  strings:
    $s1 = "YiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}