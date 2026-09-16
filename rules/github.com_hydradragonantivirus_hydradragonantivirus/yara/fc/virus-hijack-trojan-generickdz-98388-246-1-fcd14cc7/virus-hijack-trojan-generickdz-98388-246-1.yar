rule Virus_Hijack_Trojan_GenericKDZ_98388_246_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_246_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df462cf5388f32290178f622ff120a4b67405536d41dea9a73bc418b67c8508f"

  strings:
    $s1 = "naPa]\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}