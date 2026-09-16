rule Trojan_Danger_Trojan_GenericKD_67166905_130_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_130_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0986aee100c48b179567ae0f7acd5c6c8a07c71f75bef7cc121e5dfa9d7ae2c"

  strings:
    $s1 = "Bdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}