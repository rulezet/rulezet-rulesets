rule Virus_Hijack_Trojan_GenericKDZ_103285_684 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_684.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd379edcf7c95bb9bbc7b471ca55f18427cc9cb9a69472f4ea3a4e3c5d16a1f8"

  strings:
    $s1 = "`policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}