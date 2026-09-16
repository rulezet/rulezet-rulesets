rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_65_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19c985ce0a93117e3a1fa30f86e343c105af4861196ce51512da44b3aaa6c58e"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}