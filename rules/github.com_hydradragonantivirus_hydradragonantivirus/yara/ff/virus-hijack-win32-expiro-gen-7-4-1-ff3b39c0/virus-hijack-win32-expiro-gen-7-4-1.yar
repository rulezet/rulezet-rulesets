rule Virus_Hijack_Win32_Expiro_Gen_7_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Expiro.Gen.7_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d38c7ed7a33405ff4a841c63a9be3c41a613f01d89aa5541f95bb09859614dee"

  strings:
    $s1 = "EYAh$b" fullword ascii
    $s2 = "W#G@CRIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}