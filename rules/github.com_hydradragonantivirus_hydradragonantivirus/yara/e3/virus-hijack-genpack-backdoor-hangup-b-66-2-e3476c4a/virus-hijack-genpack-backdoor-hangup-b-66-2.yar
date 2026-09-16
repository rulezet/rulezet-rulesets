rule Virus_Hijack_GenPack_Backdoor_Hangup_B_66_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_66_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "622e12b21d1be2f642377aeed5ead4652f01ba51def3471c732501169c50bf0c"

  strings:
    $s1 = ",#Wran" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}