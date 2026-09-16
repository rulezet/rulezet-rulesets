rule Virus_Hijack_Trojan_Agent_DQQO_393 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_393.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25059747f78fa5f4600743604c53ae24d6a2752a1b26c17c95d986600ae63871"

  strings:
    $s1 = "orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}