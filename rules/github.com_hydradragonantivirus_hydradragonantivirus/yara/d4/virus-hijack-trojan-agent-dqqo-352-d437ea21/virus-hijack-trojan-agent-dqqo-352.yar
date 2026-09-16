rule Virus_Hijack_Trojan_Agent_DQQO_352 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_352.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef80d4a7e312482e466052f7aa808e2c57ffc4dd449f048bff37254f8431dee"

  strings:
    $s1 = "\"daRr u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}