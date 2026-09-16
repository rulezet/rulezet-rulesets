rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "359556e8ddeadd5b818a80337cf72ba8555aa8347b7afeaabd08f17a78f2a376"

  strings:
    $s1 = "vial#=@" fullword ascii
    $s2 = "Erika(." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}