rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1837df2d971720118e05b371c7f8445707a54c4244b39c78c78ecd13084a8d6a"

  strings:
    $s1 = "[by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}