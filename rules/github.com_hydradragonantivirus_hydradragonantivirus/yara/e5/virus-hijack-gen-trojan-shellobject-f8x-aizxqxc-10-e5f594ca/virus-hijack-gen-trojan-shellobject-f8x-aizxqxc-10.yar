rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f1a7a6cc3015833fde1f9d34cd7fb7ae355d2be2fc0efafc5048df51c7b7e81"

  strings:
    $s1 = "/Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii
    $s2 = "$HExA;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}