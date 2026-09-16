rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_493_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_493_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "592fe1303b30ef9521b2ebfd94fc37dcccc50394c4392e56521f1f29fb20cda1"

  strings:
    $s1 = "Gong{Rl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}