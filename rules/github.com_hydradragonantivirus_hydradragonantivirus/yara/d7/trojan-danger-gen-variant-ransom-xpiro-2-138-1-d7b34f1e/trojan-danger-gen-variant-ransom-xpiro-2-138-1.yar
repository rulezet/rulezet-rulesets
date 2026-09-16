rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_138_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b13a7e883a18e8a6bf147f636aa92c562d050523dc08ee4ecdc794d44c8c0285"

  strings:
    $s1 = "`IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}