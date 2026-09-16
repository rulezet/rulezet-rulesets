rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_705_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_705_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23d3266d0db0b368bec651d78d426bf4a7254f9c68172ae24a85ff73871ecc70"

  strings:
    $s1 = "HIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}