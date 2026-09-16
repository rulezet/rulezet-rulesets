rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3272cc2ff99f34068084cc1ab9db3e836150aac7f90c8cc5e13de530ea2ccc6"

  strings:
    $s1 = "TeRA{.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}