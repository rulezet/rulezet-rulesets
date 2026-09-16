rule Virus_Hijack_Trojan_Agent_DQQO_187 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_187.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73f5bad61f43ab79c3e3fa812a1f169d4c2f63d89b2af9f8e1b00e348fd4ccf1"

  strings:
    $s1 = "-'functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}