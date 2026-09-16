rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_176_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_176_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fcc8f793a1c93c0e1c1ec7ef00c25bb0b2d69d6764572d6bda985672b4a4695"

  strings:
    $s1 = "*vOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}