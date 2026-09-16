rule Virus_Hijack_Dropped_Win32_Worm_VB_NXJ_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "904f025ced5a9fa7b182809b6b03499403ca48abbd13ab6a41c7a01d36a36c24"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}