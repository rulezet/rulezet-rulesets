rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9ed1d292ed8822ac8bf56caa5a22c77a90cee60c970c22161f00ebf0b776dec"

  strings:
    $s1 = "Kprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "Kprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}