rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_701_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_701_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7b90c4593f6ae1165439289eba8afb13ba6d30f96331ffd77bfbaca74a0dcd"

  strings:
    $s1 = " \"If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}