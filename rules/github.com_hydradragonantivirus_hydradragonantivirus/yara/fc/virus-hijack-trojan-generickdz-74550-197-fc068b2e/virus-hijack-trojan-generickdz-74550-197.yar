rule Virus_Hijack_Trojan_GenericKDZ_74550_197 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_197.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7174d8001f70a67bf365b1755748d01f2bf8f7b0257e6c656f3fca827697e12"

  strings:
    $s1 = "NasI]=8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}