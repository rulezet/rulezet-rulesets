rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_167 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_167.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "007e93362b56f70474826023e81644dde20c39fd93d3ef11dad363082d1570b2"

  strings:
    $s1 = "Oare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}