rule Virus_Hijack_Trojan_GenericKDZ_74550_126_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_126_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ac14883a3feeae7ec2da2c4813260b3a2e81f58bea6e6b9166090c1609fbd92"

  strings:
    $s1 = "ChUN'>" fullword ascii
    $s2 = "Q}WEVe(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}