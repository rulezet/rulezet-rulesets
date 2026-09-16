rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aCEmdoo_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aCEmdoo_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2f3f2dd4ec8a94b17856d3de59b5b9e316ebf58d69f111272cbf083a237a950"

  strings:
    $s1 = "Office Telemetry Agent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}