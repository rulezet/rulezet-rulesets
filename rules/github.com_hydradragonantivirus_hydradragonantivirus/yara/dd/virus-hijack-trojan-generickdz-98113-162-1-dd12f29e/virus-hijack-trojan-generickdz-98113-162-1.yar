rule Virus_Hijack_Trojan_GenericKDZ_98113_162_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab6ce3933a791716ad0f8ac3885f9cf6d790e090d73dc9544de3e5d8a343672b"

  strings:
    $s1 = "meAk'V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}