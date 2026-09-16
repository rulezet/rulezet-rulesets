rule Virus_Hijack_Trojan_GenericKDZ_74550_335_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_335_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42daf039a1ad2561013bbde84003581b96e3690b151eb7dcdf94ae71122b8996"

  strings:
    $s1 = "/ aDdA&[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}