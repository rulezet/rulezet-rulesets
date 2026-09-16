rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "100161df0841b00329913fa35a055ce77e448ad16eca5f3dc49a47c4c346bcf1"

  strings:
    $s1 = "wuGg{p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}