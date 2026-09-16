rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_344_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_344_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc937544127b4b2bc7a2053842a67a5bc82112b80f5de738b880c93c03d8691b"

  strings:
    $s1 = "pby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}