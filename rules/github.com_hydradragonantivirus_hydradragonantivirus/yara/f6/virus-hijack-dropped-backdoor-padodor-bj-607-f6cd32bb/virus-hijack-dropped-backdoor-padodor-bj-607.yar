rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_607 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_607.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f40cc5f1bb93e3537303a6b9a4bcfed4e972e9672a742ebca3a7a075d44eafd4"

  strings:
    $s1 = "'active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}