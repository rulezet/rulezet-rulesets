rule Virus_Hijack_GenPack_Backdoor_Hangup_B_133 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_133.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e07f6a3bc0013585cf351d8bb72fcc418d4a11939544c444016fa5cc453b9c9"

  strings:
    $s1 = ">-your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}