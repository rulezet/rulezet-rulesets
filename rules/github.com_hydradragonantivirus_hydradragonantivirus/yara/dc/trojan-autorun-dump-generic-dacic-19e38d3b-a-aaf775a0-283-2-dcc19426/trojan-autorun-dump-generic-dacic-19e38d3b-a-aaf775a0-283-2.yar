rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_283_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_283_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddbef749dc538431d738a20caab93821ef5938c87aa9921b8cb0d6ef155915b0"

  strings:
    $s1 = "wamP}fs)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}