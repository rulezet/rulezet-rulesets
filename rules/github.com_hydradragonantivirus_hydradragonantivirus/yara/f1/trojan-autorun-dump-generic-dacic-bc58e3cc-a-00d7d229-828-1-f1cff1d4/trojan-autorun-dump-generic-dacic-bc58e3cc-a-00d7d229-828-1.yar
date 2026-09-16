rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_828_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_828_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d06b50c0e30c0392dceb17462ad8cbc146ce713564d1f0a43b20d9986ca82f6"

  strings:
    $s1 = "PVyour entire employee population." fullword ascii
    $s2 = " UTcH}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}