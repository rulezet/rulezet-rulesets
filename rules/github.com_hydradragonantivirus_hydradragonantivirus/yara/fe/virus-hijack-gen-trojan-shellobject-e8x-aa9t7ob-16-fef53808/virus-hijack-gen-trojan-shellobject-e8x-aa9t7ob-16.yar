rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f453e897c7f55d5bbf05a8b1eb839f7e8e5f6357974aae16f76039229cecf502"

  strings:
    $s1 = "<hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}