rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_266_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_266_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cb5599dd00935b49d6bd1003d154ad5bef3e57c33b5b8d88e0a1b5efea9240f"

  strings:
    $s1 = "jUdo>j<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}