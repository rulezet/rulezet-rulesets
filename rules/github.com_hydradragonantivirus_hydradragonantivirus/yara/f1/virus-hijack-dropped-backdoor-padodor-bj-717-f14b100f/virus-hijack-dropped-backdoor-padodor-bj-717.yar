rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_717 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_717.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68435502a97be19a2e4053c37a8b1343848954cd63926e40b7f0f4596d013fd1"

  strings:
    $s1 = "]~are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}