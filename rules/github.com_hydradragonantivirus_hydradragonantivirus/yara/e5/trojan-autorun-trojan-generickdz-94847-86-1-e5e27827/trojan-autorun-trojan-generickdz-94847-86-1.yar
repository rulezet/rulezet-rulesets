rule Trojan_Autorun_Trojan_GenericKDZ_94847_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aff55738e8d247be72f5256a468dfcced7f3e8e982acf149963f734a833fc48"

  strings:
    $s1 = "}orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}