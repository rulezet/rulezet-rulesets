rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35aaa4cabecd0baddc0e921f720a94fe31e03f8dca039c08a55df495d90e3126"

  strings:
    $s1 = "sProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}