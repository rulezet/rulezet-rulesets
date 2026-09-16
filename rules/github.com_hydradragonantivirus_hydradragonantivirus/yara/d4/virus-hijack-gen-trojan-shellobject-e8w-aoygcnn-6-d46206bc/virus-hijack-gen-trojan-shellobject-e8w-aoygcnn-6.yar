rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4a623ab58222cc74871ef248f8066a9b2c1419589dfb9138d233b061e8243ac"

  strings:
    $s1 = "V\"hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}