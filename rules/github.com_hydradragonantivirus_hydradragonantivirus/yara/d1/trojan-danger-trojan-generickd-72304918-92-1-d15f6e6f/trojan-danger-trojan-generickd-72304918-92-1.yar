rule Trojan_Danger_Trojan_GenericKD_72304918_92_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8e45392ca0c28c52fb0b34bbabe9c98e457660fe01ffdea15e9633ea6bf4ba0"

  strings:
    $s1 = "PRvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}