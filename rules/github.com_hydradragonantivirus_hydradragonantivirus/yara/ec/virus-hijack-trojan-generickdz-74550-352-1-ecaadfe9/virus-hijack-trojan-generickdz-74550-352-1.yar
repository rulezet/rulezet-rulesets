rule Virus_Hijack_Trojan_GenericKDZ_74550_352_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_352_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "559554794f456db922a3e74f26043e64bcd811490d63975d50559a761a595d79"

  strings:
    $s1 = "W(wAuF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}