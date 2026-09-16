rule Virus_Hijack_Trojan_GenericKDZ_103285_479 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_479.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a320218384408bff3e137cf83ed0240ab5993a782408b15a3aabff078c86c804"

  strings:
    $s1 = "features or not use them. For more informa tion about these features, see the Offi`" fullword ascii
    $s2 = "cAlp`Al$fAl$fAl$fAl$fAl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}