rule Virus_Hijack_Gen_Trojan_ShellObject_jzZ_aCEmdoo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.jzZ@aCEmdoo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b4775420df531ab86787250e980ecf279b9ab41b9c62a3028ec41e6ea2ac6a3"

  strings:
    $s1 = "must re" fullword wide
    $s2 = "That Factlie very" fullword wide
    $s3 = "Copyright 2008, That Factlie very" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}