rule Virus_Hijack_Trojan_GenericKDZ_105924_459_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_459_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ae4f07badd41113b898d46846de0d10e056962ef52c74c16ce5578df93b8fdd"

  strings:
    $s1 = "Z?mEMo%EI" fullword ascii
    $s2 = "=P}youP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}