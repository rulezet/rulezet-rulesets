rule Trojan_Autorun_Trojan_GenericKD_72517131_101_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9881833ea33587098c3c07f3b2f11df9207cc19ff0e8b30ff770c7522e3371f7"

  strings:
    $s1 = "]1User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}