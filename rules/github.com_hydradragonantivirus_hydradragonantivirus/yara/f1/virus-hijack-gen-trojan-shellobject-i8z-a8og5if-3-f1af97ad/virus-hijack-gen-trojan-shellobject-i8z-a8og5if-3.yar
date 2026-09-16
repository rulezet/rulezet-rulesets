rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_a8oG5if_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@a8oG5if_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e5310a9cfa2d6877b77e9efc3caa52402a8c0e34188e9fa1844789fb837f55"

  strings:
    $s1 = "*by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}