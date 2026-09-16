rule Trojan_Danger_Trojan_GenericKDZ_72354_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKDZ.72354_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "942d8ee552b5822217b5ebe5648a1e6fb22ee50d205fbb23f09b45aadf3791dd"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii
    $s3 = "Angry Angel v3.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}