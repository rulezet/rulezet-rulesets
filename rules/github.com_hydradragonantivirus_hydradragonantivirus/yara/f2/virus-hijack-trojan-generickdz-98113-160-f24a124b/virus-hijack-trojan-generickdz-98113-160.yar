rule Virus_Hijack_Trojan_GenericKDZ_98113_160 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_160.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33d50e4e0c3c2bd576ec9cf498022eca6800964b7a492155c5cad82160c7d43e"

  strings:
    $s1 = "US4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}