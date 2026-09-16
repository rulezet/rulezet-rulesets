rule Virus_Hijack_Trojan_GenericKDZ_105924_526_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_526_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2a63a48e7fa82c1e00b301a9101be79c97606e05d9b14aecddb4c4b686cbe05"

  strings:
    $s1 = "HUbB!G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}