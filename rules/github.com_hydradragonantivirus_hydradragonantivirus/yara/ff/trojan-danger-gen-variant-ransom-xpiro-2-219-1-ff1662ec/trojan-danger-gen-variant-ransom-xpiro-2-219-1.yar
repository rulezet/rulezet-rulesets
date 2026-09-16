rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_219_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b7e91fb271f5c6aa9c83d4acd11dfd941658d29f84b53be35f8bb598abf5cfc"

  strings:
    $s1 = "v%YowL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}