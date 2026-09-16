rule Virus_Hijack_Gen_Trojan_ShellObject_UzZ_aCEmdoo_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.UzZ@aCEmdoo_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8231d2075c45d310c4df66b59fe59c6789bd965d7b8a4a445420b713cfa013fe"

  strings:
    $s1 = "Copyright @ Microsoft Corporation" fullword wide
    $s2 = "Windows SDK Installer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}