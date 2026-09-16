rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_640 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_640.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5a90ee97fa517592309d26a8e5f41c0ea79af1cbb0be419e1c3067b020f3879"

  strings:
    $s1 = "7are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}