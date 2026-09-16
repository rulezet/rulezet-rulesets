rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_77_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9415eeb74396446b2f2c05ee872563c98b70ee035449f71417b867e69fe32a75"

  strings:
    $s1 = "-/and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}