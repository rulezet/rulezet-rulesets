rule Virus_Hijack_Trojan_GenericKDZ_103285_130 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_130.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d64cb490a2a01e0a68b19fe0c3dd93deae104e5572acbd6c8590e1d48ab27a89"

  strings:
    $s1 = "Opurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}