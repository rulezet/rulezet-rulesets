rule Virus_Hijack_Trojan_GenericKDZ_105924_297_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_297_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2823fce1eecd80206f85134d641d621a2e433c7755fb9da460bc91614dee46e"

  strings:
    $s1 = "G`sluR" fullword ascii
    $s2 = "PeSt$s" fullword ascii
    $s3 = "p<oban" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}