rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c955ddd1730bc084648f3ecdfa7598a31084357857c452639aa5ab071843b4fe"

  strings:
    $s1 = "Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data,`" fullword ascii
    $s2 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}