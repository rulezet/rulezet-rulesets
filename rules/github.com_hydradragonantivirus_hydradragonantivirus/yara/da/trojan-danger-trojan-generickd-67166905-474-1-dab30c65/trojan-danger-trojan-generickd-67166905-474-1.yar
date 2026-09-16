rule Trojan_Danger_Trojan_GenericKD_67166905_474_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_474_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b2f380f3148e5f83ac1d4f6f79c02bf1769cf0a68d5b4b5c4bcece7413babd0"

  strings:
    $s1 = "jlWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}