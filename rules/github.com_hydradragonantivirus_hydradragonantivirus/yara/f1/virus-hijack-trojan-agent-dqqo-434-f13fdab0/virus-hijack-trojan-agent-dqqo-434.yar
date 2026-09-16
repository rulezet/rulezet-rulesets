rule Virus_Hijack_Trojan_Agent_DQQO_434 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_434.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70c6b1085cdd68a463906baf1c59f88dbfe966af1af56baed9ae1bea34267cca"

  strings:
    $s1 = ",America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}