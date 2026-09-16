rule Virus_Hijack_Trojan_GenericKDZ_103285_212_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9fbcca7952215d9e61d46fbce309b3507b192dfaf539ce92aa426c0c3694511"

  strings:
    $s1 = "Adobe Photoshop3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}