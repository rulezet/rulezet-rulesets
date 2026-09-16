rule Virus_Hijack_Trojan_GenericKDZ_98388_120 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_120.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af6bb63fde53315119ea2cdf428954e7b070c65239e2f234b37d06bbf986428"

  strings:
    $s1 = "4?HougH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}