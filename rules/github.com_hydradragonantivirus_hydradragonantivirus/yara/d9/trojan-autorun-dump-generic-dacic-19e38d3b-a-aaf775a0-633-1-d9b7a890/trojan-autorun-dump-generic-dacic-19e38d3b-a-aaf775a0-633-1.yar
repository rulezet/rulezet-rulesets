rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_633_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_633_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "888dc922974fcb6c8186ea516dd56b50e07b97969ddf6095e4b8879841a81786"

  strings:
    $s1 = "dsare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}