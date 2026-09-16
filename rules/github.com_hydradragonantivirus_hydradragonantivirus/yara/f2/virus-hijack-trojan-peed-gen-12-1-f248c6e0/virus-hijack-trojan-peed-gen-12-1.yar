rule Virus_Hijack_Trojan_Peed_Gen_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0166d9ecd57687500ea66f069ae3accd594dead99c9b42897842504cfdb21012"

  strings:
    $s1 = "diSc]<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}