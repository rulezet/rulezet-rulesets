rule Virus_Hijack_Trojan_GenericKDZ_98113_108_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_108_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0cf0a46d32c4b88ea605198b4aa0daf69c8f4cc29225270915a65cdc3be45f8"

  strings:
    $s1 = "YEah*&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}