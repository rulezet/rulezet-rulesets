rule Virus_Hijack_Trojan_Agent_DQQO_62 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_62.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5ed696c1d3ece8b550173fbecd9f6eb312fad0b928ee71397beeb2b10774d2d"

  strings:
    $s1 = "~whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}