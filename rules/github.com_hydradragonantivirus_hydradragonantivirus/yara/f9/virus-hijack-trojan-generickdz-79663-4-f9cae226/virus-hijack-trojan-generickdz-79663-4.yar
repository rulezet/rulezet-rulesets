rule Virus_Hijack_Trojan_GenericKDZ_79663_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b2d704d3eff18ff5bbe9f1acc16d745d000572e3b9a6594e089fd41d4ec365"

  strings:
    $s1 = "this notice will include a copy of your agreemen" fullword ascii
    $s2 = "physical computer, is considered a separate computer for purposes of this agreement. This`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}