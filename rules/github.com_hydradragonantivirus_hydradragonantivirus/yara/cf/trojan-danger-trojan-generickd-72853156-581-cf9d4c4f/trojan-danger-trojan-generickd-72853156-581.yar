rule Trojan_Danger_Trojan_GenericKD_72853156_581 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_581.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82aa7e3a3af166ac6ba03cfc121ddd3672b0a6b4ad98c6effb65597a4193cec7"

  strings:
    $s1 = "TRap?<RRRRRRRRRRRRRRRRRRRRn" fullword ascii
    $s2 = "TRap?<RRRRRRRRRRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}