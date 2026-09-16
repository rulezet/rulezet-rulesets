rule Virus_Hijack_Trojan_GenericKDZ_98113_41_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95b6858a76a55abf749c613fe2f335d7526746ef336727b60770200d03b02665"

  strings:
    $s1 = "FaNg*\\\"H" fullword ascii
    $s2 = "STue]?" fullword ascii
    $s3 = " pUNgi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}