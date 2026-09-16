rule Virus_Hijack_Trojan_GenericKDZ_99416_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa5fbf57f00509adaab12cb32da17293b8444ccf7455b9929ecc830e9827f589"

  strings:
    $s1 = "EUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}