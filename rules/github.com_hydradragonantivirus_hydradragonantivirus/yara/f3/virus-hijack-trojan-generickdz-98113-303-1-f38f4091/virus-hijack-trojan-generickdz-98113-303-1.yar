rule Virus_Hijack_Trojan_GenericKDZ_98113_303_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_303_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6dad50b7ec8fb897de2227f395387c2419abc06a99e55ff489c1f2b0e5f101a"

  strings:
    $s1 = "R3T?{RuLL" fullword ascii
    $s2 = "VADE)g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}