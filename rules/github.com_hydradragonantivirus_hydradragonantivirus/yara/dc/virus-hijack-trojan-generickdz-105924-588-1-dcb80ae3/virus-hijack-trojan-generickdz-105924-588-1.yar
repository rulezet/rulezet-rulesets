rule Virus_Hijack_Trojan_GenericKDZ_105924_588_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_588_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1bf3fd2f2dc2b9d75d46b9d528f8187ff76ecea064173988d257c0cc69ab4cd"

  strings:
    $s1 = "j$nAVE" fullword ascii
    $s2 = "wQ!HUbB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}