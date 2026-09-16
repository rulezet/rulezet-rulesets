rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_aOag0Mh_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@aOag0Mh_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "261bc4abeb9f8691bc9f4b6c7c345e750136d647531031fe77b70ed3b7fc4580"

  strings:
    $s1 = "PLAY&6c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}