rule Trojan_Autorun_Trojan_GenericKDZ_94847_148_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "612067709329529de7a1e2518858d74a304a4df8742737daa4086fa400afdcbc"

  strings:
    $s1 = "QlAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}