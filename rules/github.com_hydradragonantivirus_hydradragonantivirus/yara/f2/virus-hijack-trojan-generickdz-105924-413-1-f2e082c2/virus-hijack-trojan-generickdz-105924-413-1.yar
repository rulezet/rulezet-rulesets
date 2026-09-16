rule Virus_Hijack_Trojan_GenericKDZ_105924_413_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_413_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83be74eb4d2a11e81c7ef2fc2c7751581ad82d7f06a54caa1f0d86f686a14356"

  strings:
    $s1 = "A BeMA" fullword ascii
    $s2 = "U heRe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}