rule Virus_Hijack_Trojan_GenericKDZ_105921_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "871ac2548c46097bd0aae0a0475a8300b2e40799fc3979020ac13c345a3eb844"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii
    $s2 = "'2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}