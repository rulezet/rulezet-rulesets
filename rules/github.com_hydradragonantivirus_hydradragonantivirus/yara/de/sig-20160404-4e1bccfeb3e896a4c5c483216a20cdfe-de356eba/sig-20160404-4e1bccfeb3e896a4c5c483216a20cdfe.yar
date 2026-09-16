rule sig_20160404_4e1bccfeb3e896a4c5c483216a20cdfe {
  meta:
    description = "datamaliciousorder - file 20160404_4e1bccfeb3e896a4c5c483216a20cdfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd74c2fb3afec02f7f27ba0da007f6cc50c0fb81e1fa486055501029c50a3747"

  strings:
    $s1  = "var Ww = true  , SdZX = Ine[7] + Ine[9] + Ine[11];" fullword ascii
    $s2  = "return XXRxHEO[0] + XXRxHEO[2] + XXRxHEO[4] + \".F\" + XXRxHEO[7] + XXRxHEO[9] + XXRxHEO[12] + XXRxHEO[14];" fullword ascii
    $s3  = "var Ine = (\"2.XMLHTTP DKYsmXR HdazK XML ream St liosqden AD humFYwf O jqzW D\").split(\" \");" fullword ascii
    $s4  = "var XXRxHEO = yVnBn(aBPQnmtWho+\" \"+\"System CZ DumxH Obj MKVQrU ect OCuqQZy vTbrn\", \" \");" fullword ascii
    $s5  = "pieI.open(BXqan,VWrKv,false);" fullword ascii
    $s6  = "function gUrx(mTwqM) {" fullword ascii
    $s7  = "function LuOk(qbCjK) {" fullword ascii
    $s8  = "return GTee[jYYvKY[0]];" fullword ascii
    $s9  = "function ewDx(YxKPc) {" fullword ascii
    $s10 = "return MHOXK;" fullword ascii
    $s11 = "function UTYSmK(KkPA,kzvVgk) {" fullword ascii
    $s12 = "function wsCH(qUxyU) {" fullword ascii
    $s13 = "if(H>=V.length) {break;}" fullword ascii
    $s14 = "return ICZUmwA(lP,EVnMQ[184-178]+EVnMQ[859-852]+EVnMQ[961-953]);" fullword ascii
    $s15 = "return aZsia.status;" fullword ascii
    $s16 = "function QOeek(CWBSUWmR,NGpD) {" fullword ascii
    $s17 = "if (mTwqM > 169494-623){return true;} else {return false;}" fullword ascii
    $s18 = "function sSlQCwli(oOW) {" fullword ascii
    $s19 = "if (g >= qUxyU.length) {break;}" fullword ascii
    $s20 = "return gVzk;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}