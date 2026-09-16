rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_117 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_117.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1692540ed65b3caa523e782997115682c21e5079c15edb19045d489d271c8b3"

  strings:
    $s1 = "4~Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}