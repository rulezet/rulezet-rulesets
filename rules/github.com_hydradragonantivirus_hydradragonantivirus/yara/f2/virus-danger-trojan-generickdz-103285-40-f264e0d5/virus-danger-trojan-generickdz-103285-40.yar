rule Virus_Danger_Trojan_GenericKDZ_103285_40 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3dfc816c6c79cc60f49a147d3f33c825d8f72877efc95539b058ab1cdc060cb"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii
    $s2 = "xa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}