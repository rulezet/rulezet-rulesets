rule Virus_Hijack_Trojan_GenericKDZ_105924_347_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_347_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa3b6b20db1d6dff8189b1b07fc3ff1bc5f057bfa02711670ca2b4d0854ccdb"

  strings:
    $s1 = "\",BREW" fullword ascii
    $s2 = "FN aVer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}