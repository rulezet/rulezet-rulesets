rule Virus_Autorun_Trojan_GenericKD_36668029 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKD.36668029.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d0dd9f3fccea36b475f70d1ca68dad2e434943c62b3120372cd12e917b3944"

  strings:
    $s1 = "Clock Microsoft " fullword wide
    $s2 = "Clock " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}