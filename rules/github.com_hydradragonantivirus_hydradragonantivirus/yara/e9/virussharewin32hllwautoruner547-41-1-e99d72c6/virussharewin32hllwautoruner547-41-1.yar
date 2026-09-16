rule VirusShareWin32HLLWAutoruner547_41_1 {
  meta:
    description = "datamaliciousorder - file VirusShareWin32HLLWAutoruner547_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937626d18f1e68354b43aefc092e7833333b219fce7648ca28b94f2f46f13b10"

  strings:
    $s1 = "YeSo$M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}