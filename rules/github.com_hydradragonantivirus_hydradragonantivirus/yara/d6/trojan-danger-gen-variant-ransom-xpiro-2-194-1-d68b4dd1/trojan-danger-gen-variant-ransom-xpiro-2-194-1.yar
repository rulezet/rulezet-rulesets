rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_194_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82eed74e94daa0fa12f39d0648463b4df3bdff08f67dd7ca6903aa4d68956eb2"

  strings:
    $s1 = "Ewhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}