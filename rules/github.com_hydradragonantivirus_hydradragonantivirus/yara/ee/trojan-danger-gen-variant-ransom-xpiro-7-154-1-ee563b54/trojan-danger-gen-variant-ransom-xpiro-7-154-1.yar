rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_154_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20b5a0f2759c66ef08152425c199cec100b2005bed3b06d95c1cc1e73a26cace"

  strings:
    $s1 = "You may not assign this agreement or give or transfer the programs and/or any services or an interest in them " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}