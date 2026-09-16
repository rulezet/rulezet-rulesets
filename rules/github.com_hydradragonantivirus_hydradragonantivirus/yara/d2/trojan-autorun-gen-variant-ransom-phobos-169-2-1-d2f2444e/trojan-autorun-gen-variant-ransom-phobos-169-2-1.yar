rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ad09817ff0dddfee2899e00041c63a03c8ace490ad1f514c9c57678e302d9ca"

  strings:
    $s1 = "\\or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}