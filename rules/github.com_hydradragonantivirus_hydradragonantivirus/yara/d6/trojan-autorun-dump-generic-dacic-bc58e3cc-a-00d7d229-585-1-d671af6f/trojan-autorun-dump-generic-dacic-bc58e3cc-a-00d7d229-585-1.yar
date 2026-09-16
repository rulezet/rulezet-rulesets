rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_585_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_585_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8ccb0b9742b9eaafdf74a2e32d35d1acb45482966b9930e599f6a02f9b305c0"

  strings:
    $s1 = "KBthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}