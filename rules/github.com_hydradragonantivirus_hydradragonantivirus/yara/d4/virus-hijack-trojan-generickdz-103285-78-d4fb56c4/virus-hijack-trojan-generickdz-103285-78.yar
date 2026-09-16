rule Virus_Hijack_Trojan_GenericKDZ_103285_78 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_78.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1219b7cf4698f6864d7d646d95f638fc4092ee52cac07f8435ef17db5ff9bcce"

  strings:
    $s1 = "KDOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}