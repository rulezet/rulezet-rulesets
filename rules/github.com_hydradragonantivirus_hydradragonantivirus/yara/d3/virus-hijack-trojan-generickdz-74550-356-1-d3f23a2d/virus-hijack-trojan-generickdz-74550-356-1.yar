rule Virus_Hijack_Trojan_GenericKDZ_74550_356_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_356_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fa526fb0e67ba83c326c8268e0db33cd9fce8fb7d9242aa67808e05e542378a"

  strings:
    $s1 = "jocu<$7" fullword ascii
    $s2 = "TROG[&" fullword ascii
    $s3 = ":*>ToDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}