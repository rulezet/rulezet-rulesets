rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae5e45e3945e1cfcfd6782dda62f3b23eb48132dd25a9f96d8e01fe5eacd46e8"

  strings:
    $s1 = "rby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}