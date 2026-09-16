rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_652_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_652_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d952ca950e2b5d1d7aa3f81197e255917cb954f032eeffdd90f8376e060add"

  strings:
    $s1 = "Q~oit(9*QUoit(9*2B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}