rule Virus_Hijack_Trojan_GenericKDZ_103545_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39eeff40d3f39c38f3b7ae67031fdd61bd053a4195a234b695e1d70ed5167f08"

  strings:
    $s1 = "T,sLoo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}