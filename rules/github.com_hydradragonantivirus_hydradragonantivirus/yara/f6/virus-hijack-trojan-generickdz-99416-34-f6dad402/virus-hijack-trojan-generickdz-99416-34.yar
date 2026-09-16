rule Virus_Hijack_Trojan_GenericKDZ_99416_34 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37d84ce83c54df28a51eb6bb1e69e79e3db1fad61389eece60d36fd1a147cf5e"

  strings:
    $s1 = "ZUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}