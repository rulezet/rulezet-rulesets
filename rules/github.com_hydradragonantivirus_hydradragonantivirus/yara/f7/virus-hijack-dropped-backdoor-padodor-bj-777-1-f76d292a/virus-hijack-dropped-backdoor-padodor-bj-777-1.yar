rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_777_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_777_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fd9b75518532fe07753b9fa14d4c3d35c351343ddc13fce77e9dccbab8cb98c"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}