rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_542_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_542_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6b223ca15d85f63736d9cb5a10507d4c2d8799f2902b28fe160bd1df1b7f36"

  strings:
    $s1 = "oESoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}