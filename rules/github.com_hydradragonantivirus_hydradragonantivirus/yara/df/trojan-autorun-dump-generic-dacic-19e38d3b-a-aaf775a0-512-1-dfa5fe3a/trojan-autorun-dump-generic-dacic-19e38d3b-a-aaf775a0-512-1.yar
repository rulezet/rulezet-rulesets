rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_512_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_512_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "030bed5004c8277070b94c00a584457819bddc2e4b6e2f54b81ad78f4ea12446"

  strings:
    $s1 = "]SaDe;" fullword ascii
    $s2 = " \"SaDH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}