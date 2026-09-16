rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_20_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_20_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce051287f6741679f29de440e41c0b5136b6172f1e75c34cbb3f77bcba286f64"

  strings:
    $s1 = "Portions Copyright (c) 198" fullword ascii
    $s2 = "Sync!_iz3" fullword ascii
    $s3 = "L FROM:<" fullword ascii
    $s4 = "k/)From" fullword ascii
    $s5 = ">!Aqua" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}