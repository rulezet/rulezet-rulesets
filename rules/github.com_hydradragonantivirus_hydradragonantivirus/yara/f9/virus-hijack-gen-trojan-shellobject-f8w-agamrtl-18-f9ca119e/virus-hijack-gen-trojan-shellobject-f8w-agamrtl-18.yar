rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a20bd274283dbb0e4329a036adf0cb2a93b48b88bef9ebd60ac5b637426a84e5"

  strings:
    $s1 = "|:program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "|:program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}