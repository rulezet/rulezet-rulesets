rule Trojan_Danger_Trojan_GenericKD_67269844_51_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354ee9f9ef96240012be0d381a04ece00047bfd74e3884274cff7104c5dc391c"

  strings:
    $s1 = "<message dialog." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}