rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aCkwazk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aCkwazk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "458e308763bf2c58151c3ba32bf0fcdb195aebafaf41de380809420bfd6d5861"

  strings:
    $s1 = "-]by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}