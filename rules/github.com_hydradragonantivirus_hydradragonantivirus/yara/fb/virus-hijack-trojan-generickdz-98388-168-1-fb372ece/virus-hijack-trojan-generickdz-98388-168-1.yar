rule Virus_Hijack_Trojan_GenericKDZ_98388_168_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b7d6e5c7bec63c9808c1b2a97487d02d0bd6e984c1a1de795e926f1bc7d443"

  strings:
    $s1 = "E?fEST" fullword ascii
    $s2 = "m@Slip" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}