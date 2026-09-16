rule Virus_Hijack_Trojan_GenericKDZ_103285_583 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_583.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c01413b16bbd08768ce3444ff7268ffd5fa1d0ea1987eb69cc6f54b106b3def2"

  strings:
    $s1 = "TriM#l2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}