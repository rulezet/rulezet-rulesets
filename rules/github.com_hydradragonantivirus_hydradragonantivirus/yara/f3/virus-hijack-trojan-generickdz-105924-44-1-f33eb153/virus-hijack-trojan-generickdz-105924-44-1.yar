rule Virus_Hijack_Trojan_GenericKDZ_105924_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57f8f9d5c0e84b05124acb423844b05e36d78e521aca51ec1cba06a316ed0b9e"

  strings:
    $s1 = "*DuCHY@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}