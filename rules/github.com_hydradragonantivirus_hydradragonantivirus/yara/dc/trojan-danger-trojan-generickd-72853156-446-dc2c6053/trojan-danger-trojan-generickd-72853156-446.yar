rule Trojan_Danger_Trojan_GenericKD_72853156_446 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_446.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88972cb05e1c15658088837921c67cded4a8ca85f2501554a6fac03f0a874d9d"

  strings:
    $s1 = "Task Manager.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}