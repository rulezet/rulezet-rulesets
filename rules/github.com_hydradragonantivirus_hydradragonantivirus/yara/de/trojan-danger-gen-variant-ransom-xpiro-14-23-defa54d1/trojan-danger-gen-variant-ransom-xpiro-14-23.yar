rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_23 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e668ac38fa5fe2e56a446170ab1da658d0cdefb3d7f04d1685865a647ec7e0e3"

  strings:
    $s1 = "Start Command Prompt with Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}