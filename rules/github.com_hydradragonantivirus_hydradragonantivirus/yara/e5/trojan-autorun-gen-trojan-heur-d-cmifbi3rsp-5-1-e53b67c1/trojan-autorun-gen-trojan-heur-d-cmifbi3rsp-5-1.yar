rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc07e06055723f18c8f085d81fcf1d08e6b9a12efe6925a4e8019c0db2249b6b"

  strings:
    $s1 = "Nor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}