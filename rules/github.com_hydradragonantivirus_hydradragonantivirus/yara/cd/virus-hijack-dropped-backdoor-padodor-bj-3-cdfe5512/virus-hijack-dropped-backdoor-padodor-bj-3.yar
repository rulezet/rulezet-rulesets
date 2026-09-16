rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "918bf8d259c87c7e885e15772b3f5d967cc3da33b766194e89fcdcf33a8fd837"

  strings:
    $s1 = "s/and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}