rule sig_20160314_80ed9ba1b2c442e8a77407e38280f641 {
  meta:
    description = "datamaliciousorder - file 20160314_80ed9ba1b2c442e8a77407e38280f641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00d63c1eafcb113bb744d08924f9991eb143ae55398107d35db8d399955afbf7"

  strings:
    $s1  = "var VP = true  , zNlw = dGk[7] + dGk[9] + dGk[11];" fullword ascii
    $s2  = "return zoXAQlx[0] + zoXAQlx[2] + zoXAQlx[4] + \".F\" + zoXAQlx[7] + zoXAQlx[9] + zoXAQlx[12] + zoXAQlx[14];" fullword ascii
    $s3  = "MwYGO.open(YRORZ,aYzgW,false);" fullword ascii
    $s4  = "var zoXAQlx = \"Sc uhESSgQ r Zcvwfepta ipting iSMsTjt fBt ile eSCMQDnuDTqgpB System iZ IqNML Obj WKYHjm ect ByMxjMq Gtwgw\".spli" ascii
    $s5  = "var zoXAQlx = \"Sc uhESSgQ r Zcvwfepta ipting iSMsTjt fBt ile eSCMQDnuDTqgpB System iZ IqNML Obj WKYHjm ect ByMxjMq Gtwgw\".spli" ascii
    $s6  = "var dGk = (\"2.XMLHTTP QteGVrS qvzjz XML ream St FmPblKCT AD pxpGpmX O rWEC D\").split(\" \");" fullword ascii
    $s7  = "if (I >= nNYAT.length) {break;}" fullword ascii
    $s8  = "function nOmr(AAIlQ,Wjjrt) {" fullword ascii
    $s9  = "return yvrt.ExpandEnvironmentStrings(oHKnb);" fullword ascii
    $s10 = "if(F>=j.length) {break;}" fullword ascii
    $s11 = "function rFlR(QdiLQ) {" fullword ascii
    $s12 = "if (EPpeC > 162845-342){return true;} else {return false;}" fullword ascii
    $s13 = "function PAYZJbVgH(lMRTFRuFOWK) {" fullword ascii
    $s14 = "return msIi.responseBody;" fullword ascii
    $s15 = "return zICXndd(fd,uXbVu[224-218]+uXbVu[372-365]+uXbVu[717-709]);" fullword ascii
    $s16 = "function VxQD(RUoKC) {" fullword ascii
    $s17 = "function TXnTqoY(msIi) {" fullword ascii
    $s18 = "return xHATE.status;" fullword ascii
    $s19 = "function GRrN(EPpeC) {" fullword ascii
    $s20 = "function pcKR(nNYAT) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}