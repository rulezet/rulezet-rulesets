rule Virus_Infector_Win32_Expiro_Gen_7_33 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9c62d5237fb90fa178b445de5b9c104ea65845e522415d470f0b7efc09dd755"

  strings:
    $s1 = "($hakU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}