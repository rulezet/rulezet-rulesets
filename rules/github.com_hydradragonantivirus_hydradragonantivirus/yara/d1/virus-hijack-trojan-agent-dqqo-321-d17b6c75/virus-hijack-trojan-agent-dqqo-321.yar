rule Virus_Hijack_Trojan_Agent_DQQO_321 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_321.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35d9cb7a89f137a987af863426dc7edb1e194d380f7380e2c889256405f14c24"

  strings:
    $s1 = "~orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}