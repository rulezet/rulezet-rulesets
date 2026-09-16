rule Trojan_Autorun_Trojan_GenericKD_72517131_179_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_179_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9bc4067d1779c6343eaa439a4e8f78c48bc8e47e7e7debfbcb36a476fd73cd7"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}