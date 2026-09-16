rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d20041d05f01bf1ba3b7ecc5a1ec1c034eecaf178a34fa660e0d6adc4bbdeac"

  strings:
    $s1 = "y?hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}