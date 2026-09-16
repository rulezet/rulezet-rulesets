rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aqza5Lj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aqza5Lj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d473536f5d4dc3d84514f1115f0c664551aabfc9fbfe31b57e781c3d31029a37"

  strings:
    $s1 = ")America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}