rule Virus_Hijack_Trojan_GenericKDZ_74550_355_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_355_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3132b59a0ebe40779b4746da57da13d58c103236453093432e2ee5348205ab08"

  strings:
    $s1 = "`MEiN ioBc" fullword ascii
    $s2 = "\\!Feck" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}