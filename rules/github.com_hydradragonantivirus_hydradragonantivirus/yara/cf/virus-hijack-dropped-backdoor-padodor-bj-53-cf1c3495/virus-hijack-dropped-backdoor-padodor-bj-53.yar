rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_53 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "139285d560a04594788898afd1166df54e171f385927301e5705fedee9005472"

  strings:
    $s1 = "Microsoft products. You agree that w`" fullword ascii
    $s2 = ">Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}