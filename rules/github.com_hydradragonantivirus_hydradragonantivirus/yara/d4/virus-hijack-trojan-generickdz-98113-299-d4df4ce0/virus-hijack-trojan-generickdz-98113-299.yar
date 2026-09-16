rule Virus_Hijack_Trojan_GenericKDZ_98113_299 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_299.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70227672997017c2cac2f239348bf544140ec5ae7133d2152a7642b6b44ea58"

  strings:
    $s1 = "cby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}