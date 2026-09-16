rule Virus_Infector_Win32_Expiro_Gen_7_78 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_78.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2339ea323d05412e8ddb5d75b57b6240e2f1b03e4e1ac9aad224c67ea1ea23e8"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}