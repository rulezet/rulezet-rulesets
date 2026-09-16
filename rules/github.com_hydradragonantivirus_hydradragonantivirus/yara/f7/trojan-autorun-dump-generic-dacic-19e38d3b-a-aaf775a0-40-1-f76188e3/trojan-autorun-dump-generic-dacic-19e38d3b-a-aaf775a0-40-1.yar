rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_40_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e7dd7a552112218ccc3b7587919eb6a3ae071ca626856f05a558308a89d419e"

  strings:
    $s1 = "@lIRA?IR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}