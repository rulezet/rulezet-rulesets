rule Trojan_Danger_Gen_Trojan_Heur_cuY_HPIO3zfb_20_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.Heur.cuY@HPIO3zfb_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34f600f3075a74b06323cefe18866d928c661a66da2ecd2ceacefbeb69adfc77"

  strings:
    $s1 = "-orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}