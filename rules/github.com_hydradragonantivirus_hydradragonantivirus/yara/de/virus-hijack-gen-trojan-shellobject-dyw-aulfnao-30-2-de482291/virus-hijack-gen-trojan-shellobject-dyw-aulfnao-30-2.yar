rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_30_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_30_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71df4ef91330b1a43d3f84c7ae47f274827f87427ba75b9c3697223ed3d95851"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}