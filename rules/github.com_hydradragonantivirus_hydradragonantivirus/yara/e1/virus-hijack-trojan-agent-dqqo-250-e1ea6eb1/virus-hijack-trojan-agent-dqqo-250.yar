rule Virus_Hijack_Trojan_Agent_DQQO_250 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_250.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92914ced61df363f10b21d286fc87955a8309d973a0c6e1476ac6b5c2db3dffb"

  strings:
    $s1 = "!OAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}