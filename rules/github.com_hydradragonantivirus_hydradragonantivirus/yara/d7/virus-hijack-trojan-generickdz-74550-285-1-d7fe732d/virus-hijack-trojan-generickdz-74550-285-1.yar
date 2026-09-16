rule Virus_Hijack_Trojan_GenericKDZ_74550_285_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_285_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c411084c6ab9f37b2f25b5505c5a4ee67d0863bd79701857fb3e4462a2f7da"

  strings:
    $s1 = "v aNSu" fullword ascii
    $s2 = ";`wOpS" fullword ascii
    $s3 = "`)GolD" fullword ascii
    $s4 = "StaM}`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}