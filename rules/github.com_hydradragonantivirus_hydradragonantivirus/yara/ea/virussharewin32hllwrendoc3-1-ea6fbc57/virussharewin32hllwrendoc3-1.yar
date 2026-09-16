rule VirusShareWin32HLLWRendoc3_1 {
  meta:
    description = "datamaliciousorder - file VirusShareWin32HLLWRendoc3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c614fd9a439ee18db9156e3b8d5033137690e386f0cf7d028037fa3cf3503499"

  strings:
    $s1 = "a<YOGH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}