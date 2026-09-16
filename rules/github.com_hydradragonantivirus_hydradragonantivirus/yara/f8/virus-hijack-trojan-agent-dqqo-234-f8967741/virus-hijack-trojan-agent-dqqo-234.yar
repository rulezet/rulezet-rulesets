rule Virus_Hijack_Trojan_Agent_DQQO_234 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_234.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "480050dbf43a68880e123fbe100766310c1577ae219b3223c6ea2e3c30421670"

  strings:
    $s1 = "?[whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}