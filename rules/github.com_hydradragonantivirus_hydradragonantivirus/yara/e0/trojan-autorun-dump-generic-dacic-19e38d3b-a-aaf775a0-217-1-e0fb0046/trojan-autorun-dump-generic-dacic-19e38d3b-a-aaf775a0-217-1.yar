rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_217_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4d3fd978a7aec20855abce1f992350e7231043d581cc013350c68086ec96de6"

  strings:
    $s1 = "$posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}