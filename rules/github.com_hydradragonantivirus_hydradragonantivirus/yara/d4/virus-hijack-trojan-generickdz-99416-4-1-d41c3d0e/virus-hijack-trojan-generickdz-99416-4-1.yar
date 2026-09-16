rule Virus_Hijack_Trojan_GenericKDZ_99416_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12d6d30ba6332cc7ca70963bd558f5cb985b7299544d818cdc3abece16294857"

  strings:
    $s1 = "4(REcK" fullword ascii
    $s2 = "chabl6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}