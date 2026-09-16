rule Virus_Hijack_Trojan_Agent_DQQO_365_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e518add6b7b8b24208216c76f13b79f66243054165b97a753736222a5c6458d7"

  strings:
    $s1 = ",Reference Viewing Condition in IEC6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}