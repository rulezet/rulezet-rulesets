rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_454_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_454_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6380f72a9ae4ed9311b8097e8a9a385954202ee79724bbcc3a0faa6054a4a23"

  strings:
    $s1 = "of Subscribers. If your busines" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}