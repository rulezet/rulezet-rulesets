rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_a0YNrLh_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@a0YNrLh_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bbf3c7f9bd654a11e596dce367c1bcdfd01e1c88353d01531e90d444450bc27"

  strings:
    $s1 = "[message dialog." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}