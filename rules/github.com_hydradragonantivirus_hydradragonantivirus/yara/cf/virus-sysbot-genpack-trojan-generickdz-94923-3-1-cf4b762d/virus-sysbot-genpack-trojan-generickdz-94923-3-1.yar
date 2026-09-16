rule Virus_Sysbot_GenPack_Trojan_GenericKDZ_94923_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11066c2e0a1b0fe58bc9584918054340aa58179a79a3c8c6da49c63801d8ff2a"

  strings:
    $s1 = " Operating S" fullword wide
    $s2 = " Microsoft Corporation. All rights reserv" fullword wide
    $s3 = "Background Intellig" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}