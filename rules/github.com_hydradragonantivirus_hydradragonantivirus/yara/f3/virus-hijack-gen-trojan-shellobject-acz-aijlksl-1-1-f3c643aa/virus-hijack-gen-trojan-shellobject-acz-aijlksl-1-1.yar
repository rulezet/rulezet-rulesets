rule Virus_Hijack_Gen_Trojan_ShellObject_ACZ_aijlKSl_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ACZ@aijlKSl_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18f38030fbf453082925499e5a2e3eb476e47c432fe6fc0e75222eb6d9a6a984"

  strings:
    $s1  = "'Object dump comple0" fullword ascii
    $s2  = "enough spasw" fullword ascii
    $s3  = " properly saved across a functio" fullword ascii
    $s4  = "number ~d!" fullword ascii
    $s5  = "base >," fullword ascii
    $s6  = "The value of ESP was not" fullword ascii
    $s7  = ">?DAMAGE: a" fullword ascii
    $s8  = "block type." fullword ascii
    $s9  = "UQMessage != NULL" fullword ascii
    $s10 = "hance M" fullword ascii
    $s11 = "Aebytert#aRia#Ereab#yeens" fullword ascii
    $s12 = "s Retry" fullword ascii
    $s13 = "n call.  This " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}