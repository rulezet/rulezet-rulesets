rule Virus_Hijack_Trojan_GenericKDZ_105924_121_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdf33981db2af7e8ef22f2578388800bad15333c5c788c3d846b15c097d79a45"

  strings:
    $s1 = "liSp -" fullword ascii
    $s2 = "doOl][S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}