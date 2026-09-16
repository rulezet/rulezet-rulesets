rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_79_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1f2546ca38c9429a6b0a856c96b47c16a2b0f9e3b629bb4efa3d89b7784639"

  strings:
    $s1 = "N@If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}