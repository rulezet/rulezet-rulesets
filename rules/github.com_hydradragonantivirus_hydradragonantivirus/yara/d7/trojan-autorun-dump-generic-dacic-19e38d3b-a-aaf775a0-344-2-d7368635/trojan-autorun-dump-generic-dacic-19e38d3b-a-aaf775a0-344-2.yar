rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_344_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_344_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e269355445b70397f7c8607c12c5010fa25010717851dce4318e120d43aa60e7"

  strings:
    $s1 = "e%KUDu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}