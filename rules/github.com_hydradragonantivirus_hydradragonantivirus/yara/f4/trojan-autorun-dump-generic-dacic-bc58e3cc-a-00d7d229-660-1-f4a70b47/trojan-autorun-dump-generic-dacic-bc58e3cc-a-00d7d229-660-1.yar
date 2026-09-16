rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_660_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_660_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a201ecf0f6cc690e8f1abc13c1b113e4a5d04ff22d50cb3723e4813b9955864e"

  strings:
    $s1 = "ficreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}