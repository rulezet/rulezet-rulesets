rule sig_20160314_ca5634320b9fa5d90aa2fcf345d570e6 {
  meta:
    description = "datamaliciousorder - file 20160314_ca5634320b9fa5d90aa2fcf345d570e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01b6749c0e3669e482fe396749cbf085adc9e9a9b22f308cf47e45be0b3f1715"

  strings:
    $s1 = "cNspjbpw.open(EqdwLbRmVY + ilIELaNPCzXKYuh, Hmll + QzkUCbmyvlf + jfIuAwgukVtsq + zUDLCjOZjh + Dmifspgglwds + CKASdIAG + WEx + nc" ascii
    $s2 = "while (cNspjbpw.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return Wlx + nmVvwwOOmGx + kHwCimhygpJRLZf + rDOFxQX + KGBSW + QxedPgRJ + ttnxSEdjoCPYN" fullword ascii
    $s4 = "function iElYCtfloYJAeQ(fname)" fullword ascii
    $s5 = "function UOBjQjAekCUmsB(n)" fullword ascii
    $s6 = "var ltJORXMKoSdEB = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}