rule Virus_Hijack_Trojan_GenericKDZ_98113_298_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_298_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c0497af67200503cdd4b92a765d8ccfeb6d8fb3c0c4baa6225c371d50c2a114"

  strings:
    $s1 = "LiME]nk" fullword ascii
    $s2 = "7{haRD" fullword ascii
    $s3 = "5]Noun" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}