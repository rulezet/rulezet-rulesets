rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_392 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_392.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b192d3f5430d7bc20d9cd91329be087394828cc4e20e15247efbdeba3e39d136"

  strings:
    $s1 = "cY\\[aNON!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}