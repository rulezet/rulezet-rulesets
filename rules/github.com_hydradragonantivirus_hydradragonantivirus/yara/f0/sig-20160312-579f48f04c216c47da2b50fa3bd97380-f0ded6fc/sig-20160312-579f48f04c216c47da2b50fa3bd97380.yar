rule sig_20160312_579f48f04c216c47da2b50fa3bd97380 {
  meta:
    description = "datamaliciousorder - file 20160312_579f48f04c216c47da2b50fa3bd97380.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd53fa3bcd760bbf2969982808f8aedf74c5ecee81d338e6ced08b0f2c1ef716"

  strings:
    $s1  = "var wk = true  , RxAV = Ddu[7] + Ddu[9] + Ddu[11];" fullword ascii
    $s2  = "return qHGGLCI[0] + qHGGLCI[2] + qHGGLCI[4] + \".F\" + qHGGLCI[7] + qHGGLCI[9] + qHGGLCI[12] + qHGGLCI[14];" fullword ascii
    $s3  = "var Ddu = (\"2.XMLHTTP dTLmgzE BqKVg XML ream St NpXFUAUz AD PjRhJdt O uSvR D\").split(\" \");" fullword ascii
    $s4  = "ytpxy.open(SefUG,rehyd,false);" fullword ascii
    $s5  = "var qHGGLCI = \"Sc DidDdtV r HGWASxPWP ipting JmJnvTu nqk ile aLhUdyshHMsgEJ System sE grned Obj wXEDnd ect UhuKbJl\".split(\" " ascii
    $s6  = "return new ActiveXObject(DyAkYE);" fullword ascii
    $s7  = "function AYsN(cWSkR) {" fullword ascii
    $s8  = "function axvkHQv(PZJP) {" fullword ascii
    $s9  = "return cOijx;" fullword ascii
    $s10 = "function pnmyCLjL(oRF) {" fullword ascii
    $s11 = "return CJuOU.status;" fullword ascii
    $s12 = "function NaVydUzih() {" fullword ascii
    $s13 = "return jqRVXl.position=492-492;" fullword ascii
    $s14 = "return MrLreQI(NK,dKCVi[709-703]+dKCVi[245-238]+dKCVi[206-198]);" fullword ascii
    $s15 = "return oRF.size;" fullword ascii
    $s16 = "if (K >= tPqEr.length) {break;}" fullword ascii
    $s17 = "return TRVsRYj" fullword ascii
    $s18 = "function aZor(ytpxy,rehyd,SefUG) {" fullword ascii
    $s19 = "function yhUnn(DyAkYE) {" fullword ascii
    $s20 = "return PZJP.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}