rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_419_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_419_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc1ee6766c6c4ecad814f2d3e18fab7cbea7e1a0d9a1a1dc1a6759e3f7fd6d"

  strings:
    $s1 = "~are a part of the software and may not be used s" fullword ascii
    $s2 = "g]ya rule" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}