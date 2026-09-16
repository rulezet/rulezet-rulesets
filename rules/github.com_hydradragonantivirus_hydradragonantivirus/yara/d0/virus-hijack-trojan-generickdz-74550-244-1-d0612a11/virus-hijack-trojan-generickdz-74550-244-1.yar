rule Virus_Hijack_Trojan_GenericKDZ_74550_244_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_244_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc6faa26467577c9a5bcdfff1bf970b8bce17d9731af7835409b7328caab5fc"

  strings:
    $s1 = "F gauS" fullword ascii
    $s2 = "f[kEtO" fullword ascii
    $s3 = "m]iMPy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}