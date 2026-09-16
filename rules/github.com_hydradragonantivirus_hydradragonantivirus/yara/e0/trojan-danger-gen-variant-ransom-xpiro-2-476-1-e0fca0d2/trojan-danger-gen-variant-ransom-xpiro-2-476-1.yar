rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_476_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_476_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3efed836f58422f59b366472c27069ae69b947439201eee14b1e2bfe8ab4da3"

  strings:
    $s1 = "S\\available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}