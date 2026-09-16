rule Trojan_Danger_Trojan_GenericKD_67166905_48_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "862261839068bb32ed1832ace0df05130979d8e2f88e412f867c18ce4a0ba467"

  strings:
    $s1 = "&bLEO." fullword ascii
    $s2 = "frIt'r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}