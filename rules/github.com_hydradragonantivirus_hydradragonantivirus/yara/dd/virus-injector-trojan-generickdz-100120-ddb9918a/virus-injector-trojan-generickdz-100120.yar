rule Virus_Injector_Trojan_GenericKDZ_100120 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.GenericKDZ.100120.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e99247369384ab07ccdd9a965bdef5e96d57867e59552c174f54a651714f4a9d"

  strings:
    $s1 = "\"hALo{" fullword ascii
    $s2 = "tHEmA." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}