rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_475_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_475_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd52ed1b9b7754acc34bb0f9448e7735565185b2460f493f00345b4dbf6379de"

  strings:
    $s1 = ")Resource instance not specified, did you call CommonLibraryDllProcessAttach?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}