rule Trojan_Danger_Trojan_GenericKD_72677122_27_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "216d4e54da4f6859e89b955b5ea47d05838545f948321c60f8fd10cf9ad2afca"

  strings:
    $s1 = "%RuNt>" fullword ascii
    $s2 = "*~<fOun." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}