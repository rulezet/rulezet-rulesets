rule Virus_Hijack_Trojan_GenericKDZ_98113_422 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_422.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "febb091fbfe76f88e72f9cb7546b447af6dd068ccb15da9251544cba4d093fd0"

  strings:
    $s1 = "+} PelT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}