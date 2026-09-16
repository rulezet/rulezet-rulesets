rule Trojan_Danger_Trojan_GenericKD_67166905_36_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0770a230615f3dfd1a7e7238827136f65dc1fbd65c350e6ca0af1d817e65e19"

  strings:
    $s1 = "RRWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}