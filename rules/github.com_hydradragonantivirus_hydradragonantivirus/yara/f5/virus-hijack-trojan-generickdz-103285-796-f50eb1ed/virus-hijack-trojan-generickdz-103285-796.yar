rule Virus_Hijack_Trojan_GenericKDZ_103285_796 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_796.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0630c0858ace1e6f5838897a5e3da2d76c1f6f946c789d5d3f8082b1003f6778"

  strings:
    $s1 = "Gpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = "AedN@etNA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}