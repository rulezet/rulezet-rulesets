rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_a0Pysxf_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@a0Pysxf_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73b951d8c84b894b0e1cb3f83f7f44af1e2b8d6a98064c79be6b57f016b836f2"

  strings:
    $s1 = "Microsoft Client" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}