rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5bf3f913150cb4255d2ed58cd806449d3d3b009218db3937e912ca4c9a821f2"

  strings:
    $s1 = "!This program cannot be run in MZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}