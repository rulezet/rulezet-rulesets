rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_668_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_668_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b055641161499de7d5054b0afae094f263d1f93983447839d064fa45db6936f2"

  strings:
    $s1 = "If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}