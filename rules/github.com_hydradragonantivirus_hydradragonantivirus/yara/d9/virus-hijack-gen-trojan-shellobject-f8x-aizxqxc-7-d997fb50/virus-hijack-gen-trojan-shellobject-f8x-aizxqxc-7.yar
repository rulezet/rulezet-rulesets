rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e54de6d768a20541a8c13e25bc2bef712d79f9882073ec1e9c1630005752095a"

  strings:
    $s1 = "=Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}