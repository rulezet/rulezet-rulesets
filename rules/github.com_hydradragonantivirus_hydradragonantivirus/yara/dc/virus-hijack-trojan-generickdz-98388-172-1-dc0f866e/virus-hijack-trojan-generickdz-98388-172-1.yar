rule Virus_Hijack_Trojan_GenericKDZ_98388_172_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_172_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99e70fa0bd422d8ab1105f216d62df9359a221cd16433f8b9c0fd8ef8311ee0b"

  strings:
    $s1 = "waiK>;u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}