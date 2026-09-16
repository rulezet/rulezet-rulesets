rule sig_20160405_e81d77881e32c3381ad13fedeede3cb9 {
  meta:
    description = "datamaliciousorder - file 20160405_e81d77881e32c3381ad13fedeede3cb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46e1e353f3791df2ebabc3e1c8a3098e0e0c570213a5db01adf0012e21c4abca"

  strings:
    $s1  = "return qipHqcB[0] + qipHqcB[2] + qipHqcB[4] + \".F\" + qipHqcB[7] + qipHqcB[9] + qipHqcB[12] + qipHqcB[14];" fullword ascii
    $s2  = "var Iy = true  , KoHV = keH[7] + keH[9] + keH[11];" fullword ascii
    $s3  = "eqOg.open(AwYtH,nOvfm,false);" fullword ascii
    $s4  = "var keH = (\"2.XMLHTTP HpEQMSb USoIu XML ream St MmrLuXVu AD OfDDPXL O QxYi D\").split(\" \");" fullword ascii
    $s5  = "if(W>=H.length) {break;}" fullword ascii
    $s6  = "return qWpx;" fullword ascii
    $s7  = "function xZphc(AFdAkj) {" fullword ascii
    $s8  = "function RgDe(gxTKy) {" fullword ascii
    $s9  = "function sneXmLG(gLcg) {" fullword ascii
    $s10 = "return bhFPb;" fullword ascii
    $s11 = "function qmfON(XnNewkTp,OneA) {" fullword ascii
    $s12 = "return gLcg[MSCSYF[0]];" fullword ascii
    $s13 = "var eRYsHBa = \"uvhaou*ptR*pt.S\"+\"hell*ABIoZHp*Scri*\";" fullword ascii
    $s14 = "return NxF.split(lsamq);" fullword ascii
    $s15 = "return bAdgOGu(wg,iDeha[952-946]+iDeha[347-340]+iDeha[374-366]);" fullword ascii
    $s16 = "function wxXX(urDDp,WnbAR) {" fullword ascii
    $s17 = "if (xeZMS > 168250-895){return true;} else {return false;}" fullword ascii
    $s18 = "function QaGE(TdTXM) {" fullword ascii
    $s19 = "iWH = W; break; " fullword ascii
    $s20 = "function sfTI(kTLQy,rQnpA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}