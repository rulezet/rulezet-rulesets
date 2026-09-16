rule Virus_Hijack_Trojan_GenericKDZ_94849_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7351771dc755c161ebacd0a9679c4af27c38746d5079378b87bbde6825390539"

  strings:
    $s1 = "ShIm)];" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}