rule Virus_Hijack_Trojan_GenericKDZ_74550_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a0df5227f914339a9c6c4da3cdcdf23e7a70aabd1655c7e3157185f4384c47f"

  strings:
    $s1 = "@,w dd<sOka" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}