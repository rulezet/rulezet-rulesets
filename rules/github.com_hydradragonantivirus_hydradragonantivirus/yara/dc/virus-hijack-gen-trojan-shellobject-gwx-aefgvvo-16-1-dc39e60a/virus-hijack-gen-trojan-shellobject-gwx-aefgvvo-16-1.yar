rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fde47189be3759015296ae9c092dea1317127e530b27543d1c7e8ff05ae78161"

  strings:
    $s1 = "Perjurous" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}