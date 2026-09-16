rule Trojan_Danger_Trojan_GenericKD_67166905_20_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea0608dbdd44677ed3153feb2d77cf4a70a5643a29074bee60aa088e11736891"

  strings:
    $s1 = "USoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}