rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_am0pOwg_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@am0pOwg_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e5cab880268f538d1fc0c584a010e00f0196c258b8936138489bcfe6fbe0589"

  strings:
    $s1 = "lete Obj" fullword ascii
    $s2 = "li} has made a.tC" fullword ascii
    $s3 = ". ??e{flat}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}