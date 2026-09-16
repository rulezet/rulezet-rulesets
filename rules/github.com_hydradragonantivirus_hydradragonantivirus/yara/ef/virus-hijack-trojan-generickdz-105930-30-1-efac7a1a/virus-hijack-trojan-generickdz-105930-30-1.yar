rule Virus_Hijack_Trojan_GenericKDZ_105930_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9801085aa7130c62dd6ceeeda21aaf0c4a8942df4553b987b2662b8b7f7fbb17"

  strings:
    $s1 = "#sHUN]" fullword ascii
    $s2 = "fAnD{f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}