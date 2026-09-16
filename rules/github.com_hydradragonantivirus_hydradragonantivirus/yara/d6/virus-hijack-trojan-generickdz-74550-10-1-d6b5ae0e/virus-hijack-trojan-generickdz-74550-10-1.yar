rule Virus_Hijack_Trojan_GenericKDZ_74550_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5dd937bf4395df83d4fc13aa27917b900490692cf967b46a8757b17b1c09caa"

  strings:
    $s1 = "AtAp;y#" fullword ascii
    $s2 = "rANG,[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}