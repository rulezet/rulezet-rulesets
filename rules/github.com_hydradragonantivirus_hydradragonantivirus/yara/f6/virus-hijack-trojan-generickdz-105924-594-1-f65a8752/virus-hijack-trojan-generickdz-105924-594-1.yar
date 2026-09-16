rule Virus_Hijack_Trojan_GenericKDZ_105924_594_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_594_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "319c33213318c7b201247ee1089dac8b91cff46f73e4ba0942f0260da8f3682a"

  strings:
    $s1 = "A]EYED" fullword ascii
    $s2 = "Wage([+" fullword ascii
    $s3 = "TGPP%b]oHiA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}