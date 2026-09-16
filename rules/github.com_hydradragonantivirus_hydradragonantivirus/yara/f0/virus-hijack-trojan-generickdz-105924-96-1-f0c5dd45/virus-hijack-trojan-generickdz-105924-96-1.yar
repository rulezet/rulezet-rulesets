rule Virus_Hijack_Trojan_GenericKDZ_105924_96_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_96_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15c4d4c8adb7ee42c5224fda17e19626d0f264dcc971e1a8ccfee7e5e63f8968"

  strings:
    $s1 = "Urde)+J3_U" fullword ascii
    $s2 = ",@TaKt" fullword ascii
    $s3 = "=[ruEr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}