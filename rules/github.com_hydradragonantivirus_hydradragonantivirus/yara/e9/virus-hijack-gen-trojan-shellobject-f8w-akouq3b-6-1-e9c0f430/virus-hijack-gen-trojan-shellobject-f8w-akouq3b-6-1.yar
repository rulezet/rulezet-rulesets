rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51d638e80280de28a5cd3dff266278c43d582366f61379ec73ff8e3eda2561c5"

  strings:
    $s1 = "On&Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}