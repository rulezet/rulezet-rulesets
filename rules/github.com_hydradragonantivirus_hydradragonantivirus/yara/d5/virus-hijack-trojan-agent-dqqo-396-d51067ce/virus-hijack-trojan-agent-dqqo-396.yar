rule Virus_Hijack_Trojan_Agent_DQQO_396 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_396.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b09c4e186b5d170975dcc5e5c17358a2bc8fc4a9a453fdd433c51f990e9c566"

  strings:
    $s1 = "?8automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}