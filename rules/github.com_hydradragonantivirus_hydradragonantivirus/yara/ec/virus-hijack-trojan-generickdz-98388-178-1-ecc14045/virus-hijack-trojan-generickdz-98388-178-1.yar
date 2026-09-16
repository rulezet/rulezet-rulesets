rule Virus_Hijack_Trojan_GenericKDZ_98388_178_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c297859cca3181dbe4887a804fa43c77babe5a1e49932cbd98c2dcfe2061502"

  strings:
    $s1 = "`!desS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}