rule Virus_Hijack_Trojan_Peed_Gen_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b893ba43cba1d1b5cc65c8fd9f30920177e78b7d1a0ef5746e914779b737af71"

  strings:
    $s1 = "=[MIxY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}