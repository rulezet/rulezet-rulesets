rule Virus_Hijack_Trojan_GenericKDZ_98113_326 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_326.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09cc68159a9ac7ec1ac8e6d07f3a229e7bcf2362c329281bd0a837c3f2217bc"

  strings:
    $s1 = "_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}