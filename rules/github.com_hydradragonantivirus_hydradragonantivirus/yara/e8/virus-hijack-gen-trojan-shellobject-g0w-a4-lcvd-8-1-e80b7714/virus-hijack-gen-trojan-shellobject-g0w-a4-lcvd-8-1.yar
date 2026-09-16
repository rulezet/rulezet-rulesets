rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad5516436062596446375c7b46f90c8c37dac165d8128520e0f01c3292011259"

  strings:
    $s1 = "LakE,#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}