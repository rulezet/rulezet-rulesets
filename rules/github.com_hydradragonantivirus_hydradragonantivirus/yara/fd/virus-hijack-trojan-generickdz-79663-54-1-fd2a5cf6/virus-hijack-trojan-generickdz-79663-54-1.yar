rule Virus_Hijack_Trojan_GenericKDZ_79663_54_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "030e532cbe266fb12bf573764f98187f6b935ff9278d2bfb07999d52a385b726"

  strings:
    $s1 = "MUra$\\" fullword ascii
    $s2 = "f,once" fullword ascii
    $s3 = "Rapt}N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}