rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51f8cbf6e8c73ee71297f256edfa99601c1a5b25c86595729ce9fae67ff2803f"

  strings:
    $s1 = "\",StEP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}