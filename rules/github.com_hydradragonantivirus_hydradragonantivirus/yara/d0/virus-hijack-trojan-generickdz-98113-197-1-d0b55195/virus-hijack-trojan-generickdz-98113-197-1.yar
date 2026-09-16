rule Virus_Hijack_Trojan_GenericKDZ_98113_197_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_197_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ebecefb17f47dd4c39ca5d4882ec4277626164a8d381bb5f4e9a14f352416f1"

  strings:
    $s1 = "O=~)SCUt" fullword ascii
    $s2 = "[&aMic'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}