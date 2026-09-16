rule Virus_Hijack_Trojan_GenericKDZ_103285_422_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_422_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2ace9372510f35a35450a28821e77ee8a30a4265ee1e9143a7a99ab395b7f4"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii
    $s2 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdfAli stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}