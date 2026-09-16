rule Virus_Hijack_Trojan_GenericKDZ_98388_249_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_249_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c07c55eaf72d90de8564120133b4693aa3d2103908ebb51b751e78e1713c0538"

  strings:
    $s1 = "S-$GaPA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}