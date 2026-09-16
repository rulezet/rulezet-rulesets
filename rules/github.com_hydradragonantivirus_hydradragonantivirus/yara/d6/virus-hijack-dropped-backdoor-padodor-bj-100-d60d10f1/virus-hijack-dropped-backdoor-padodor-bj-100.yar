rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_100 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_100.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93f9ba5116244854d3c04d7baa45a18d35ca58f262767118c947dd93aa96fc39"

  strings:
    $s1 = "@Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}