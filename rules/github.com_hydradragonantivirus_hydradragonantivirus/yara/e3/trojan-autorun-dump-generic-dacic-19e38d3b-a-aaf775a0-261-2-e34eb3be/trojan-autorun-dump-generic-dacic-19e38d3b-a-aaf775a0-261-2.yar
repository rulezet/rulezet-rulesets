rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_261_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_261_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640584644919d13e8595997d2875c3ef4afb11adeb97331428ce9abfa6f733bd"

  strings:
    $s1 = "fRAP&zVM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}