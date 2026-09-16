rule Virus_Hijack_Trojan_GenericKDZ_98113_113_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_113_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a113e0aa6dcd12c0b66c158cea52a5b82fa71d7da1441653c780dd5af414ae21"

  strings:
    $s1 = "DOER IM*N" fullword ascii
    $s2 = "?>wAtt" fullword ascii
    $s3 = "CRow:$" fullword ascii
    $s4 = ")YeLd`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}