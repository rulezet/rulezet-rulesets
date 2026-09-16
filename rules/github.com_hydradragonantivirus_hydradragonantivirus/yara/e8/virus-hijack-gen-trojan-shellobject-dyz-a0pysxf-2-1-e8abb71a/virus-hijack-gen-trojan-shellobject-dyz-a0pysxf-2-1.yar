rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_a0Pysxf_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@a0Pysxf_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdd728b59ba9d1b1e71db77a2ef7816f8f3b62aa8c7e65899e5d9fd23efc943b"

  strings:
    $s1 = "Microsoft Client" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}