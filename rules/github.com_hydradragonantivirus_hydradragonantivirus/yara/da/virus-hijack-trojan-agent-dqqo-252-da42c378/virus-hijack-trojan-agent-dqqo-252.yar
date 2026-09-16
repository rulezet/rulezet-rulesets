rule Virus_Hijack_Trojan_Agent_DQQO_252 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_252.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cde029f2e12608c574adc3b8313ce03296b848dd2aa9af3086574ba801b5d067"

  strings:
    $s1 = "JAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "BLEE#b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}