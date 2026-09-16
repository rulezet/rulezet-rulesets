rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_205_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_205_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fcf66cc5691822cb450bce2f17148e3afbc77c2258b93dbf3985cffcc4d2ac2"

  strings:
    $s1 = "Please Login First" fullword ascii
    $s2 = "local clr-namespace:ValorantLogin.View" fullword ascii
    $s3 = "Forgot Password?" fullword ascii
    $s4 = "Password :" fullword ascii
    $s5 = "Doesn't Have An Account?" fullword ascii
    $s6 = "Register Here!" fullword ascii
    $s7 = "Segoe Print)" fullword ascii
    $s8 = "Ini Dashboard Eakk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}