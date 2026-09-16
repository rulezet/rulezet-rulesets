rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea67ef6d5e6efd13738c3a70c7399a7b074a41a0913e6f8cde2b8e58fa61d288"

  strings:
    $s1 = "\\Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}