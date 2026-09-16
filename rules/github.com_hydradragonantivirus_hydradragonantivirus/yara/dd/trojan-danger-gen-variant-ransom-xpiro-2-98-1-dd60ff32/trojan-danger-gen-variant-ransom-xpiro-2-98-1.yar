rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_98_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06f7a1b201c5ae0ed2a01d9622445ca7cb8716b9b44d0d29f8a236fb0755fb02"

  strings:
    $s1 = "KWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}