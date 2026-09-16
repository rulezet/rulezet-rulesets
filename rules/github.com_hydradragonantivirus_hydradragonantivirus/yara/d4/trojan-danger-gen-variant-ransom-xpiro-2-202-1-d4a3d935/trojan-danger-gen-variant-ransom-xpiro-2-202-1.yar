rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_202_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_202_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1d174fdb6259fa533410f791f9b9124d77bfe2f20aa0b16d795e520f470f1dd"

  strings:
    $s1 = "DODO,<D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}