rule sig_20160307_2adb8326404d4c91840e39712bdbf225 {
  meta:
    description = "datamaliciousorder - file 20160307_2adb8326404d4c91840e39712bdbf225.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccb02c9c170d0e675877ace74f8c8ffe6a051070bbb87940981d7b07af416b96"

  strings:
    $s1  = "return OwWFMtt[0] + OwWFMtt[2] + OwWFMtt[4] + \".F\" + OwWFMtt[7] + OwWFMtt[9] + OwWFMtt[12] + OwWFMtt[14];" fullword ascii
    $s2  = "var nmt = oRPP(hipE + \"B.\" + zXK[5]+(360720, zXK[4]));" fullword ascii
    $s3  = "var yY = true  , hipE = zXK[7] + zXK[9] + zXK[11];" fullword ascii
    $s4  = "OnwpL.open(gjUNQ,zored,false);" fullword ascii
    $s5  = "var zXK = (\"2.XMLHTTP vkgIZgV TFENz XML ream St eOqbUOIa AD OdHzicx O dsfO D\").split(\" \");" fullword ascii
    $s6  = "var OwWFMtt = \"Sc gWzbbQE r kkoCGeVgO ipting zvTUHEb PWm ile YlgLUuDpNNshsC System zr ubDIA Obj gMmjrs ect eqBwKDH\".split(\" " ascii
    $s7  = "if(c>=O.length) {break;}" fullword ascii
    $s8  = "function QXJhmCgEW(yppMSnknPSQ) {" fullword ascii
    $s9  = "function nuSb(hfdhe,ivbdL) {" fullword ascii
    $s10 = "function GpFf(OnwpL,zored,gjUNQ) {" fullword ascii
    $s11 = "function lOQxbfoL(FFO) {" fullword ascii
    $s12 = "if (GWJQr == 1059-859){return true;} else {return false;}" fullword ascii
    $s13 = "function TKbp(tneYv) {" fullword ascii
    $s14 = "function oRPP(ZHqfJ) {" fullword ascii
    $s15 = "return OZtoL.status;" fullword ascii
    $s16 = "Vwp = c; break; " fullword ascii
    $s17 = "return lrMhh;" fullword ascii
    $s18 = "function emZngliaK(XFFJV,pkQPG,DDpPS,AczX) {" fullword ascii
    $s19 = "function JoaF(kBSDO) {" fullword ascii
    $s20 = "return Sh.ExpandEnvironmentStrings(vXUCo[6]+vXUCo[7]+vXUCo[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}