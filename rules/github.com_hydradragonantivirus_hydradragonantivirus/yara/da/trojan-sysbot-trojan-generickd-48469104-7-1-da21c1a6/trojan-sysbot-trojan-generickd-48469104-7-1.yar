rule Trojan_Sysbot_Trojan_GenericKD_48469104_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.48469104_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2bfd1948670e09b8080929b69ae0c84e099cad7b97cb7ab8263696e2367f269"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}