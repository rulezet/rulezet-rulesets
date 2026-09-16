rule Virus_Hijack_Trojan_GenericKDZ_105924_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d96c900431dc8a789a63fa825dd7e29fbb75e19821fd9f5943030abda0116f13"

  strings:
    $s1 = "(*agar" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}