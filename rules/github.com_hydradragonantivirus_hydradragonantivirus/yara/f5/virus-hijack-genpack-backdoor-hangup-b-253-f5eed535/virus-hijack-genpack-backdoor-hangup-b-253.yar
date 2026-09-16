rule Virus_Hijack_GenPack_Backdoor_Hangup_B_253 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_253.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "095fa7bf26c2226f95028fd417ed0b461e5c782ffe2ddbfe308ebdcebf77b31f"

  strings:
    $s1 = "FXyour entire employee population." fullword ascii
    $s2 = "+!cRap" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}