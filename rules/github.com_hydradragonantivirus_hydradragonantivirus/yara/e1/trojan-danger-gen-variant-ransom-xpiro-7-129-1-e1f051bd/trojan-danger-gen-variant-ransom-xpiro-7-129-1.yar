rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_129_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_129_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eacec64a6e943864409ab9fe13a245a7888bf1680403728b015b085873fe609f"

  strings:
    $s1 = "'a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}