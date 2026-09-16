rule Virus_Hijack_Trojan_GenericKDZ_105924_419_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_419_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d7b1d5e232f98e18c1ba2e6d35f38118132ef34f6c966725cba6944c7078fde"

  strings:
    $s1 = "SLow#N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}