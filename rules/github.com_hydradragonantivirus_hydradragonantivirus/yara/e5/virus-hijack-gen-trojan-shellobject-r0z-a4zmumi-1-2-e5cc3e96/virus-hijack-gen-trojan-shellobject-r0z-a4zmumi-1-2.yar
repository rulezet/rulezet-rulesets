rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7c742f64a65ed8f42391628c8281ca428048d1e1afddf5234d1d7e8da65cacf"

  strings:
    $s1 = "DEAf]A`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}