rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_55_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64eabeeba82802be0d01505977f7cd79134f05b1ba50037df516074920c3ef2c"

  strings:
    $s1 = "s prior written consent.00" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}