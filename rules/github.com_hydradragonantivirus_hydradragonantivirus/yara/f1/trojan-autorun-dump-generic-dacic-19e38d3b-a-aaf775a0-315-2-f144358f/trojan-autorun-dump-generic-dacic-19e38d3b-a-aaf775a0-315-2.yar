rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_315_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_315_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eb357c7519eea1bf1269e5f4f033074170a194c05f05ad439bc98eb26d5560c"

  strings:
    $s1 = "masK*7-}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}