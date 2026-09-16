rule Virus_Hijack_Trojan_GenericKDZ_105924_353_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_353_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d82cf0bcee856b4fcac8e62e80c604d66aafdd47f503bf51e2f76bb1efd8d35"

  strings:
    $s1 = "kaNa[FY" fullword ascii
    $s2 = "B,wHEt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}