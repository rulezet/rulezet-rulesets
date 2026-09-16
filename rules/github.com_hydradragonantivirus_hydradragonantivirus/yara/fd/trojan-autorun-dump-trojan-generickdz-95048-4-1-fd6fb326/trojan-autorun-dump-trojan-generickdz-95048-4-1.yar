rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e98242b49c9fa95805781c81ac8bc1eb40503b0f45a07b1d3d621e66cb94cb2"

  strings:
    $s1 = "HAND[%/d:%/0" fullword ascii
    $s2 = "SAND[%/\\8%/0z%/\\8%/0*%/0:%/0:%/0:%/P:%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}