rule Virus_Infector_Win32_Expiro_Gen_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7204e0b8cadc698b1d6792af6866c357dcdaa2892e1427283a779e82bc3db21d"

  strings:
    $s1 = "*epHa?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}