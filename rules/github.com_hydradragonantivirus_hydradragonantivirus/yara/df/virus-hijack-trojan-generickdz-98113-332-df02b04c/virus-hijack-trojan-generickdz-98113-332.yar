rule Virus_Hijack_Trojan_GenericKDZ_98113_332 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_332.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0081db1cdb904ebc865e7637b2b39007107e8e7c2eb46e4ec3d236aecf7f348"

  strings:
    $s1 = "}yEAst" fullword ascii
    $s2 = "<[D\\tuCAf{EAst" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}