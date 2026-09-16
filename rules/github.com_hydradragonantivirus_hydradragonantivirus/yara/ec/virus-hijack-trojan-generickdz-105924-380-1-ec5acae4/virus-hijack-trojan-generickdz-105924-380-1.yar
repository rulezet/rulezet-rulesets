rule Virus_Hijack_Trojan_GenericKDZ_105924_380_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_380_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "532dee00d1b4e2368298442b62fa638be15a1934689364415659a4807e71b925"

  strings:
    $s1 = "E*sOOL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}