rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3b882d539ef21184d5bb00d9994bfe9b5d2572fc1abf94bb4b5ef5d8a8922fc"

  strings:
    $s1 = "\"jWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}