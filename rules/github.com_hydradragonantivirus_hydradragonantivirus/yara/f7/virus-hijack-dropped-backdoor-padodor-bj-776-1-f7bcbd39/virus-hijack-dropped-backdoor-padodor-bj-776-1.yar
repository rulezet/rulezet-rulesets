rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_776_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_776_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c5195849af8357bd9ef8ad44f9ae1909440e246a47c6ac2b68e05c10cde461"

  strings:
    $s1 = "Outpitch" fullword wide
    $s2 = "Beatae" fullword wide
    $s3 = "*456*-@36*=.42+?Kamas" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}