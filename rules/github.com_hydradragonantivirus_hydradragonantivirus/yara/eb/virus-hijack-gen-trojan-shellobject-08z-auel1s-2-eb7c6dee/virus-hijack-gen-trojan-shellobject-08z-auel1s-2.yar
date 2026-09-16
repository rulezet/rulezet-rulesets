rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "566de487464a901b8f96e5083351ab966a1300484ffef3adc71b336c3906e320"

  strings:
    $s1 = "1Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}