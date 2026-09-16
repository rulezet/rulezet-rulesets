rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bbbb35d815d6ae5a6b49374995296a6794be514ac73b8a94740fe671bf1c4cf"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}