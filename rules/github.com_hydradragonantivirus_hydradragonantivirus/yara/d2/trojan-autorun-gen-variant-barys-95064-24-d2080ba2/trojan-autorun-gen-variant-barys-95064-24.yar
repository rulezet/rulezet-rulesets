rule Trojan_Autorun_Gen_Variant_Barys_95064_24 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b299398aeb7755124b06f143ccb2d01c58e496de5a34ab9cf72efc2fdb2ae671"

  strings:
    $s1 = "DyEr?q," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}