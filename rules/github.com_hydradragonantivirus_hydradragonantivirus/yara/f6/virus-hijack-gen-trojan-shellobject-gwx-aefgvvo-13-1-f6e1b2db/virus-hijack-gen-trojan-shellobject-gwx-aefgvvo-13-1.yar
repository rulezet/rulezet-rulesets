rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61477996d43684e27149f153cf2fbbc7a056cb8c287586c01b91ef92269b7bd0"

  strings:
    $s1 = "Amercement" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}