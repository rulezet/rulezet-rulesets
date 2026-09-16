rule Trojan_Hooker_Win32_Floxif_A_53 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06369245f90d7cb0b51739cb9acae1479bbd8412389d05731587043dda17b8b7"

  strings:
    $s1 = "   <description>PAOT</description>" fullword ascii
    $s2 = "yiLt'&2:" fullword ascii
    $s3 = ";SCoT]h}" fullword ascii
    $s4 = "_\"GenU" fullword ascii
    $s5 = "4,fEmE" fullword ascii
    $s6 = "Lown#R" fullword ascii
    $s7 = "M*LImb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}