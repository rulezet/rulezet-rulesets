rule Trojan_Autorun_Trojan_GenericKDZ_95048_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89724779db8eaac27f9d551a02a95c0b826c776669716944b4c8e552ab1992bb"

  strings:
    $s1 = "/orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}