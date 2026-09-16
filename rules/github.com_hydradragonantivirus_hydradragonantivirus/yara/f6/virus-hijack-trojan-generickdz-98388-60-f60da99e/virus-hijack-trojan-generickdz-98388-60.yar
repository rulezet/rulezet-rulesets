rule Virus_Hijack_Trojan_GenericKDZ_98388_60 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71387681347eddcafd6a4f5c2fdeb199a110c1c9f3d82508934bb259d95ba0c9"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii
    $s2 = "z,month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}