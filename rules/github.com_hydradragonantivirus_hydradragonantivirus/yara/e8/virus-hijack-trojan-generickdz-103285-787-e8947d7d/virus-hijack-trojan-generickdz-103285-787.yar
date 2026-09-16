rule Virus_Hijack_Trojan_GenericKDZ_103285_787 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_787.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55e5addbe9ed583e2ca37fdc7d535211fc0e285dd6d9448c57165a8a0daa0cf1"

  strings:
    $s1 = "&Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}