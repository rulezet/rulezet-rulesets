rule Virus_Hijack_Trojan_GenericKDZ_74550_241_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_241_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d490950b027a21093fb8b5d351399a60379767e0e6b612be009f27e4ad26a27"

  strings:
    $s1 = "g[tIRE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}