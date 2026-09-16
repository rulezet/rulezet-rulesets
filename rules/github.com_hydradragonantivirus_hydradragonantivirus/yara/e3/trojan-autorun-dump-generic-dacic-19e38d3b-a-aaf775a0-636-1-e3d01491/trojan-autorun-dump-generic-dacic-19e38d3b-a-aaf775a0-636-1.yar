rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_636_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_636_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "127960a269ce4016a14675222b01fdf8aafd641c12e3ada3e3e3f8dbbd72702d"

  strings:
    $s1 = "<are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}