rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_342_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_342_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c567bcfe50a6894d43a4b85b302b6f76dc6376d64eb60270e92617a20c5a789c"

  strings:
    $s1 = "e%KUDu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}