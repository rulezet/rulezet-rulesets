rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca21ab81d2dde9c873ad26f3eebc1e7b7018e623e61c8e67158685aa6ab379ee"

  strings:
    $s1 = "=policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}