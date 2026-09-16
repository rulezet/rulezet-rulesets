rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_545_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_545_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be34f68c222c1515d434b7ab4023fbf48563e712805ebb8aba3069875e433526"

  strings:
    $s1 = "$your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}