rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a4226b7b0791fe873c098ab17bf38642b823ebf31ddd742bbbb1a18519e2407"

  strings:
    $s1 = "TProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}