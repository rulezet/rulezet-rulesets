rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_93_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c0a350dd456cbb68b9ecc0120a1547aa192d5b433c60883e7bec9472f714c57"

  strings:
    $s1 = "(\\must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}