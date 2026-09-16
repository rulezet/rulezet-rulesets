rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_494 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_494.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e992895a0e6edf24f2a85d7fb5bac028fa03daa581cf8b317a28eadd92399c5b"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim unde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}