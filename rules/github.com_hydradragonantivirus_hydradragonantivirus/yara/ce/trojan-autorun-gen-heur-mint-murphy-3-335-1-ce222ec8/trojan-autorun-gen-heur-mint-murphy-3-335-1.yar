rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_335_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_335_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8e862fbb39e5244c51a2a50cac0176bf8ebb3918a41b03bf603e6b06c3d4972"

  strings:
    $s1 = "fby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}