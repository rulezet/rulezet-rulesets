rule Virus_Hijack_Trojan_GenericKDZ_103285_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a0629b18923ea0563e517a15f67533399d6e10a0fe60dc5f62ec3c53598f513"

  strings:
    $s1 = "|b<RAun" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}