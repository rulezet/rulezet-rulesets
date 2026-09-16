rule Virus_Hijack_Trojan_GenericKDZ_103285_117 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_117.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1484d7b7adc0efe0eb0da772dd64388d1b49042d40f7fccda8c0b1d1c1cdd11"

  strings:
    $s1 = "Bfa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}