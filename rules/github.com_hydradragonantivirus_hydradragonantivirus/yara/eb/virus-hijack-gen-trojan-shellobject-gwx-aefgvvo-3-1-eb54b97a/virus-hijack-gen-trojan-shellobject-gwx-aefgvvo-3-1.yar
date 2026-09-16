rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96fd5b4df1c2085f149d60b5379c1c5a923ce01dab76c98f1505ac2e2dc3f5e3"

  strings:
    $s1 = "Insanitary" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}