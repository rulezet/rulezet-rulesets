rule Trojan_Autorun_Gen_Variant_Barys_121928_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b548b75d5749f9b6773dd6cb978b1b939a9be937dc3944cd5f8a839a53ba89b3"

  strings:
    $s1 = "\\by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}