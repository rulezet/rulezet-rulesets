rule Virus_Infector_Win32_Expiro_Gen_7_160 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_160.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e1772de486f6e5287b219ae68effb01206fc464865a20f6dce8f3f95739eaa9"

  strings:
    $s1 = "sHor{fB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}