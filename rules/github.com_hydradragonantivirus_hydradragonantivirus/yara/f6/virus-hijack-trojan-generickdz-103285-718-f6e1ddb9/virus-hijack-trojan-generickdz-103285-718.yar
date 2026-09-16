rule Virus_Hijack_Trojan_GenericKDZ_103285_718 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_718.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1800e505224b4d65e53fa310bde1b68043eb9cd79bc29dd677d82f5fe92fb725"

  strings:
    $s1 = "HUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}