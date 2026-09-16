rule Virus_Hijack_Trojan_GenericKDZ_105924_52_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_52_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "389c2f28dd94f5a61b883b5a102df636debfd72ec5c86406af5deafd8c25c76d"

  strings:
    $s1 = "=$PONg" fullword ascii
    $s2 = "0&itEM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}