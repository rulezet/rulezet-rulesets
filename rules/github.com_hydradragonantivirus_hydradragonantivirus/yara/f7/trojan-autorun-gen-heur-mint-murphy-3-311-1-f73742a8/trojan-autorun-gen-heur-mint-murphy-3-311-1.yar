rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_311_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2036482d36f4480fd74443347159b8ad0eae5446661cd3c4c4762134a883d0aa"

  strings:
    $s1 = ".Nor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}