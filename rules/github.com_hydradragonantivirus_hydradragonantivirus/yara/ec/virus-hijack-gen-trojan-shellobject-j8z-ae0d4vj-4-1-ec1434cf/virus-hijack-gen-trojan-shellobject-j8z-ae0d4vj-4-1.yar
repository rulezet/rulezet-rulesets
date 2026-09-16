rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4710e9227ab01319cc9d1375494f3d8b94ca0db8525a3fa5e4af52219f4c17a"

  strings:
    $s1 = "must re" fullword wide
    $s2 = "That Factlie very" fullword wide
    $s3 = "Copyright 2008, That Factlie very" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}