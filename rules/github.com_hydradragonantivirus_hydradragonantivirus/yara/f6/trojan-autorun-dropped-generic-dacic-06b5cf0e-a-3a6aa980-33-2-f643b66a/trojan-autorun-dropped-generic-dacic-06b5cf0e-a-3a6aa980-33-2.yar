rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_33_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_33_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8016a5990bf3b99560f987e4c21956d070f74235663df450c7dcbc6c1785ff"

  strings:
    $s1 = "BiTO?P" fullword ascii
    $s2 = "SiNd*^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}