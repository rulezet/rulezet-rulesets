rule Virus_Hijack_Gen_Trojan_ShellObject_B8Z_aeuJE7m_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.B8Z@aeuJE7m_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b9bdd208700cab1333a9bde987cb9fda1f041d7ea7da7773e25396fa08a9c80"

  strings:
    $s1 = "tm,MiCO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}