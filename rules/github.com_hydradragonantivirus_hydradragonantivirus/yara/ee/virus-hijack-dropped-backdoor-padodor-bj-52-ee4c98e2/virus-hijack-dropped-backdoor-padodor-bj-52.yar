rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436416a5368fcce33130a253aa87b5b95a96c45bccc7330a258b44d9eaafce44"

  strings:
    $s1 = "active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}