rule Virus_Hijack_Trojan_GenericKDZ_105924_495_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_495_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa57f9e047628a23c8182b31bb5e7300eedf29e5e3f38eeb7d828352dc7083ea"

  strings:
    $s1 = "hEle(|0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}