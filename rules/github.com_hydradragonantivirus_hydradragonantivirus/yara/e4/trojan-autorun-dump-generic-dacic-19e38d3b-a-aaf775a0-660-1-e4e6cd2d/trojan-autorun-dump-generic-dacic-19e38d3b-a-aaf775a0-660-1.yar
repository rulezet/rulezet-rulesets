rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_660_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_660_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f120816670e3d908af2088a3a71bd6758e1cf0d7b71e06e0836d21243270fe7"

  strings:
    $s1 = "of Subscribers. If your busines" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}