rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_411 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_411.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b57ac4b73c20e2e71cd705fd6d344042a4a17933ca9a0e2a915643772132c06c"

  strings:
    $s1 = ";iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}