rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_328 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_328.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8aa36d5ab1fc98fed588e565376c52fd36a8553e7c4ff03905f1941957980d9c"

  strings:
    $s1 = "Mare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}