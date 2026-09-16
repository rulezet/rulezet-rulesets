rule Virus_Hijack_Trojan_GenericKDZ_74550_309_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_309_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c054f504177c67a95258d09e4e917f96ff0222a3f4e7160fe7d9c9c6b3eb2e10"

  strings:
    $s1 = ")kIEL]" fullword ascii
    $s2 = " ABac%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}