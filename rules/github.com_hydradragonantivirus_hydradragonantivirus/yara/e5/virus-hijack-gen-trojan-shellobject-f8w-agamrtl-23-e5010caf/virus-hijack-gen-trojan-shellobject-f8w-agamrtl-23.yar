rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e275dac0e8c52257b64df8f74bd36006971e3192d49b73d87a24a181eb97a437"

  strings:
    $s1 = "Jprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Jprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}