rule Trojan_Danger_Trojan_GenericKD_67166905_77_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b858baf3b7602179c85812f48dc64a5940b6b7df83d1023864b00d0a4026a58"

  strings:
    $s1 = "tComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}