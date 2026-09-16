rule Virus_Danger_Gen_Trojan_ShellObject_f8W_aGAMRTl_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f8W@aGAMRTl_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba894ee654a9a9b0f5b87aa7dee66a37b3b35dabcb60966c06d6626f59f14f7a"

  strings:
    $s1 = " lprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = " lprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}