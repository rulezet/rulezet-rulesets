rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_399_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_399_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2e4142fdbf3234a19748b222635cc323d388f2972a205855992134a8775a5a4"

  strings:
    $s1 = "Nand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}