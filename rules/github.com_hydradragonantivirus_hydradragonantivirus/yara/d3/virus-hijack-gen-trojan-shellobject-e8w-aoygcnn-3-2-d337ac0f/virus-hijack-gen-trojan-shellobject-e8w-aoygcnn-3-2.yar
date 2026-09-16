rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb966ba4c9124ca33dd3def3d15ce619d3c0fd32e1c9c1fc553e6f4ca2d8ff73"

  strings:
    $s1 = "iP>HuSK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}