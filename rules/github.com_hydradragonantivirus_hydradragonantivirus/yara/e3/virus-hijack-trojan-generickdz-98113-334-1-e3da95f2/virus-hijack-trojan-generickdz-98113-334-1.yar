rule Virus_Hijack_Trojan_GenericKDZ_98113_334_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_334_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f78a1e8d1eff5dbbc9d5b50e7e58086cb127ec8e6ffa449e371408392ec9a26"

  strings:
    $s1 = "W[tHuG" fullword ascii
    $s2 = "%oshaC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}