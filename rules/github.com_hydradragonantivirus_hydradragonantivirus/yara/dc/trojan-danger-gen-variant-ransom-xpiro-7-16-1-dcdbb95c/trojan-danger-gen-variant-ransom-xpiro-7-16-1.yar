rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de34f98e08685a2dc305e185c28b1a932f3bee9616edb41c207141496fa37ded"

  strings:
    $s1 = "vmicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}