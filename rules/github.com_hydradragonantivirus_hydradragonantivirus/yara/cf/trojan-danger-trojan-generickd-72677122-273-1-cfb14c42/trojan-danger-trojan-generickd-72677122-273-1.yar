rule Trojan_Danger_Trojan_GenericKD_72677122_273_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_273_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68fe73928c9cdcbfec4766884f66fab5ae680e81efcadffe6939b5e490ce1962"

  strings:
    $s1 = "dynamic method does not support fault clause" fullword wide
    $s2 = "corporation plan11 Co.,Ltd1#0!" fullword ascii
    $s3 = "corporation plan11 Co.,Ltd0" fullword ascii
    $s4 = "%Copyright plan11 All rights reserved." fullword ascii
    $s5 = "Copyright plan11 All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}