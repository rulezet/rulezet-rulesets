rule Virus_Hijack_Trojan_GenericKDZ_103285_531 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_531.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6e4435b024dec6e385d65724227259198011a474225f592067f2547859b72fb"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii
    $s3 = "^7giving rise to the dispute, and the relief requested. You must send any Notice of Dispute by U.S. Mail to" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}