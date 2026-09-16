rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff8d5dd1f0c6632cdcc3af441a113f8ba9764e3055c11594f18a4a35024cddf"

  strings:
    $s1 = "Khundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}