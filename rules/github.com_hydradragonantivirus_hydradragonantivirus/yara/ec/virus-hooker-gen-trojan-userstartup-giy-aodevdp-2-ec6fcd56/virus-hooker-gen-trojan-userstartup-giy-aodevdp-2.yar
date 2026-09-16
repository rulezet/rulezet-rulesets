rule Virus_Hooker_Gen_Trojan_UserStartup_giY_aODEVdp_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Trojan.UserStartup.giY@aODEVdp_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5643943a7ceea71e11d8116270137dc96782a806d3058adceb312c81c6d5c048"

  strings:
    $s1 = "oNly *y" fullword ascii
    $s2 = "*}sYnC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}