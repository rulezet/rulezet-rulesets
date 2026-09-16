rule Virus_Hijack_Trojan_GenericKDZ_103285_188 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_188.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6a5a312414e257aa70c251477773daba1e7be30b89445b74bbd5a95ec4b9749"

  strings:
    $s1 = "5virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}