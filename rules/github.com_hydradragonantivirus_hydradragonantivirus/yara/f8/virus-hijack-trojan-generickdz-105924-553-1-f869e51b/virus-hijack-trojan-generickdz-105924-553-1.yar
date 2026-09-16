rule Virus_Hijack_Trojan_GenericKDZ_105924_553_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_553_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5de5372786702162d7fbbae9c9450fa53fcb7cb8a96557ccbedb110874b4a4"

  strings:
    $s1 = "SoLEs$wb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}