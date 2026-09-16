rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aGAMRTl {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aGAMRTl.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6680e5b41397814874277d00b697a6116d9a249bd4cf4ad71263bf26afbd3b61"

  strings:
    $s1 = "fprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "fprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}