rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b6d6c0ba587687b71d313e1c7158c20952b0ca496494bd1dab8def4fde690a8"

  strings:
    $s1 = "Pby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}