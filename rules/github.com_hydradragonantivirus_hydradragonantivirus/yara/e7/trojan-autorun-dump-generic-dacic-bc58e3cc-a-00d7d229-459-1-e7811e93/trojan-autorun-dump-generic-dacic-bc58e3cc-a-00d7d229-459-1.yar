rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_459_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_459_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42d3f8baf47e5ffad07b984f80dfb242cfddd8762971dde92297db2e35422aa9"

  strings:
    $s1 = "~are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}