rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e03ecfb5c848e7bb4126fabfac284ff4073637a13907be94ec975f159a302e4a"

  strings:
    $s1 = "eWfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}