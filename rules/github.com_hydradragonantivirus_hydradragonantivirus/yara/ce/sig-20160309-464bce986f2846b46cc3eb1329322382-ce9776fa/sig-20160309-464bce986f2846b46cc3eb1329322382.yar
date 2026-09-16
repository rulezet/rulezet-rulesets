rule sig_20160309_464bce986f2846b46cc3eb1329322382 {
  meta:
    description = "datamaliciousorder - file 20160309_464bce986f2846b46cc3eb1329322382.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5366aa490d938767905162b1d80cd02eecd8553fbaac058505ab83c49d485316"

  strings:
    $s1  = "return uUvXgFJ[0] + uUvXgFJ[2] + uUvXgFJ[4] + \".F\" + uUvXgFJ[7] + uUvXgFJ[9] + uUvXgFJ[12] + uUvXgFJ[14];" fullword ascii
    $s2  = "var jQ = true  , ndeY = YXu[7] + YXu[9] + YXu[11];" fullword ascii
    $s3  = "var uUvXgFJ = \"Sc ZRXHcUa r QVFGyefgW ipting PnEzvni UEF ile sZSdmgthjfkCtF System nt REejO Obj RwUzbh ect NpyhaOV\".split(\" " ascii
    $s4  = "cGFEp.open(ZNLDR,mRvjc,false);" fullword ascii
    $s5  = "var YXu = (\"2.XMLHTTP QwKnkXk DEsBk XML ream St kXybegMW AD fgFvuoB O ooMX D\").split(\" \");" fullword ascii
    $s6  = "function thADPQmeZ(HfLLVVvhBqS) {" fullword ascii
    $s7  = "if (VpHWi == 454-254){return true;} else {return false;}" fullword ascii
    $s8  = "function BTLL(NIgsZ) {" fullword ascii
    $s9  = "function XzevAvfl() {" fullword ascii
    $s10 = "function cFVjENDnT(qzUcJ,LQVLR,ftdQI,wLOp) {" fullword ascii
    $s11 = "function GOLp(bcVEb) {" fullword ascii
    $s12 = "function koMF(cGFEp,mRvjc,ZNLDR) {" fullword ascii
    $s13 = "function zNPb(VgHbE,GiFwd) {" fullword ascii
    $s14 = "function FCmbzgu(SMCt) {" fullword ascii
    $s15 = "function JgolaYoQ(gQa) {" fullword ascii
    $s16 = "function zrexRTD(ypog,TuraP) {" fullword ascii
    $s17 = "return bMvxlxi" fullword ascii
    $s18 = "return AMYlb;" fullword ascii
    $s19 = "function jyKQ(VpHWi) {" fullword ascii
    $s20 = "if (i >= NlZJE.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}