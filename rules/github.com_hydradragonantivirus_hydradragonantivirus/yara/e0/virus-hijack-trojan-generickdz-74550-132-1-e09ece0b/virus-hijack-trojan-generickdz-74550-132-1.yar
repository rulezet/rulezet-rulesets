rule Virus_Hijack_Trojan_GenericKDZ_74550_132_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_132_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed3bc741db89d24e6d37e034a135efcf0e36eb553037dc765d5f5ccdefaed3d8"

  strings:
    $s1 = "yoGi>QM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}