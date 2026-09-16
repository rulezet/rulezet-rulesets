rule Virus_Hijack_Trojan_GenericKDZ_98113_311_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41bc23304f2ec851eb1596c4390122fa9e7f9812360969b92ccd83c140e7a39f"

  strings:
    $s1 = ",drail" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}