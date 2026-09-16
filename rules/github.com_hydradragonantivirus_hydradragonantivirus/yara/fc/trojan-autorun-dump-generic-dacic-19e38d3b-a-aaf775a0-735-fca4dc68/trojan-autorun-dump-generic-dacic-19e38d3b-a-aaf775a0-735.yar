rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_735 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_735.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "556247f972887a43f46b93a34d8970ab7b7e2ed319a27c2604e79977d77976b9"

  strings:
    $s1 = ";#Short" fullword ascii
    $s2 = "s`Long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}