rule Virus_Hijack_Trojan_GenericKDZ_74550_144_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_144_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "511858aef312408411ccdf7ae926f64c0216f8493a50ccb18a4a67b351d3ebe1"

  strings:
    $s1 = "meRE&v" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}