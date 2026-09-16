rule Virus_Hijack_Trojan_GenericKDZ_74550_133_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56058eeffdb81e0cdf28507bf74e025d1986e89bd7ebb0c97802c35e39dd5cb0"

  strings:
    $s1 = "SIaL*l~W" fullword ascii
    $s2 = "b!EZBA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}