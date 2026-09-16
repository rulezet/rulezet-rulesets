rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33c4ef34332e39ec31c05c6f56125e120a31748eb42e5a912bf8bb692c85966"

  strings:
    $s1 = "Object dump complett" fullword ascii
    $s2 = "enough spa" fullword ascii
    $s3 = "URUS[U_" fullword ascii
    $s4 = "?Handle" fullword ascii
    $s5 = "ByteToWideChar#Loca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}