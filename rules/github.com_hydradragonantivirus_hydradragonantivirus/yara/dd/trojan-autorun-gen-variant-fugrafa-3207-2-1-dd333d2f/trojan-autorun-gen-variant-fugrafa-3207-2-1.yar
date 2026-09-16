rule Trojan_Autorun_Gen_Variant_Fugrafa_3207_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Fugrafa.3207_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24535f3e7a8875bfa5e54c1a3c7db5f83232d53cfb490a056d64cd50269853ad"

  strings:
    $s1 = "/your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}