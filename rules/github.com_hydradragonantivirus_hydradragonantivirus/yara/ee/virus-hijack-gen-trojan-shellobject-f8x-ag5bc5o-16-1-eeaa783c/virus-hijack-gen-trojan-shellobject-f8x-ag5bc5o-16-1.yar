rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a30b517bcd307646a785ed27246192a924365de84616e369705d5aff5a7074"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "About Naver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}