rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91acb1aaba5c57e2a5ba2223ca89fed912c8070f3667b4262a8c376ca219c9bb"

  strings:
    $s1 = "f`OGEE?R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}