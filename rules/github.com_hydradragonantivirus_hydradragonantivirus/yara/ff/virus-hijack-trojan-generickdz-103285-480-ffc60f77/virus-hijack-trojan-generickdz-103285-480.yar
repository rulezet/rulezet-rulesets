rule Virus_Hijack_Trojan_GenericKDZ_103285_480 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_480.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8814de7edea3a66fc11eaceaf6640d71d7050012c6b6ae1f08981a21bf2f069b"

  strings:
    $s1 = "qThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "qThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}