rule Virus_Hijack_Gen_Trojan_ShellObject_u4Z_ay8bj9g_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce28081a21f277e7fb4f6de147583fbc05759a2a343d4dce16c8965009f50b84"

  strings:
    $s1  = "Internal Compiler Bug: No runtime type matcher." fullword ascii
    $s2  = "<Button content=\"graphic(3401,2,-1,0,0,1,1)\"/>" fullword ascii
    $s3  = "<Button content=\"graphic(3423,2,-1,0,0,1,1)\"/>" fullword ascii
    $s4  = "<element content=\"graphic(3013,2,-1,0,0,1,1)\"/>" fullword ascii
    $s5  = "<Button content=\"graphic(3422,2,-1,0,0,1,1)\"/>" fullword ascii
    $s6  = "<element content=\"graphic(3011,2,-1,0,0,1,1)\"/>" fullword ascii
    $s7  = "<Button content=\"graphic(3424,2,-1,0,0,1,1)\"/>" fullword ascii
    $s8  = "<Button content=\"graphic(3425,2,-1,0,0,1,1)\"/>" fullword ascii
    $s9  = "<element content=\"graphic(3012,2,-1,0,0,1,1)\"/>" fullword ascii
    $s10 = "<Button content=\"graphic(3415,2,-1,0,0,1,1)\"/>" fullword ascii
    $s11 = "<Button content=\"graphic(3404,2,-1,0,0,1,1)\"/>" fullword ascii
    $s12 = "<Button content=\"graphic(3400,2,-1,0,0,1,1)\"/>" fullword ascii
    $s13 = "<Button content=\"graphic(3403,2,-1,0,0,1,1)\"/>" fullword ascii
    $s14 = "<Button Accessible=\"true\" accRole=\"PushButton\" ToolTip=\"true\" contentalign=\"middlecenter\"/>" fullword ascii
    $s15 = "<Button content=\"graphic(3411,2,-1,0,0,1,1)\"/>" fullword ascii
    $s16 = "<Button content=\"graphic(3421,2,-1,0,0,1,1)\"/>" fullword ascii
    $s17 = "<Button content=\"graphic(3412,2,-1,0,0,1,1)\"/>" fullword ascii
    $s18 = "<Button content=\"graphic(3410,2,-1,0,0,1,1)\"/>" fullword ascii
    $s19 = "<Button content=\"graphic(3414,2,-1,0,0,1,1)\"/>" fullword ascii
    $s20 = "<Button content=\"graphic(3402,2,-1,0,0,1,1)\"/>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}