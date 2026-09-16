rule Virus_Hijack_Gen_Trojan_ShellObject_y8Z_aatP3Sm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.y8Z@aatP3Sm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2884fa7433074f0243d8679b0e4fd11eb61123cf7eaeb212865581dbb70484"

  strings:
    $s1 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}