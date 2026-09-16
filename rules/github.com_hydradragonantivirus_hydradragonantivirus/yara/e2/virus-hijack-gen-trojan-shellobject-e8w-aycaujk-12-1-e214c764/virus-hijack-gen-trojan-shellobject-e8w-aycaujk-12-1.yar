rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc39b35fe49d2d8ffbfdbeb9f99c138919b2dc8acbfa8ee089c959b1270f1239"

  strings:
    $s1 = "aluminium " fullword wide
    $s2 = " gluttonous" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}