rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_153_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e74470575b90c72a98b48f8602e16ef22a3fb29d891cc7471fd44b42d42858e"

  strings:
    $s1 = "user minimum table in the licensing rules section" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}