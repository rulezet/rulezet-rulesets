rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_666_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_666_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11adf3ca55cf39443559d318724bb7b1f0eb4e87ae9a8749aa08027f572ca1e9"

  strings:
    $s1 = "0tIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}