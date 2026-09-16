rule Virus_Hijack_Trojan_GenericKDZ_79663_117_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_117_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f0b8da36ac7e5826a6eb15f4bbed7430029f99a459f7605f9ead6f0194e73cd"

  strings:
    $s1 = "X@lIeR" fullword ascii
    $s2 = "O\"mAKi" fullword ascii
    $s3 = "wl(FAOn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}