rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3b220b0beed59c848259acd192f36989562c4054851f33cbeb39c434fe124eb"

  strings:
    $s1 = "functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}