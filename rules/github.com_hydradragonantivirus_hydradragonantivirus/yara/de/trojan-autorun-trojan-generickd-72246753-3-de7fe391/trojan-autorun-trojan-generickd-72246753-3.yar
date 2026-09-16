rule Trojan_Autorun_Trojan_GenericKD_72246753_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72246753_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd7624d89b625add01bf784812c5f1988066cd35f9e6cac37a4b41ed77a3d3d5"

  strings:
    $s1 = "K])TOHo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}