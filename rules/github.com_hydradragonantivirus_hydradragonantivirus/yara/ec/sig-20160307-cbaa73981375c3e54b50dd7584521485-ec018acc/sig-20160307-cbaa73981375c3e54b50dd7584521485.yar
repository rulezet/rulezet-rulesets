rule sig_20160307_cbaa73981375c3e54b50dd7584521485 {
  meta:
    description = "datamaliciousorder - file 20160307_cbaa73981375c3e54b50dd7584521485.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d5b7c9570cd77e687508439ff68e0dd380826fc6bf1570c73f73a39a244fa65"

  strings:
    $s1  = "return FWixglS[0] + FWixglS[2] + FWixglS[4] + \".F\" + FWixglS[7] + FWixglS[9] + FWixglS[12] + FWixglS[14];" fullword ascii
    $s2  = "var Ls = true  , ZgoF = OAL[7] + OAL[9] + OAL[11];" fullword ascii
    $s3  = "iREte.open(bWtLK,ouBEW,false);" fullword ascii
    $s4  = "var FWixglS = \"Sc tkXeOqB r jqbTVsXYr ipting VZsCclN rsQ ile irifcqtPOxkmOo System Sb ZpAOL Obj NziBGc ect iHqKRRl\".split(\" " ascii
    $s5  = "var OAL = (\"2.XMLHTTP jXibyZt JZRhe XML ream St PRmbMqVD AD JkhayZS O QBDI D\").split(\" \");" fullword ascii
    $s6  = "function FmULhRgRD(KjrJJKSwbyY) {" fullword ascii
    $s7  = "if(a>=j.length) {break;}" fullword ascii
    $s8  = "function chkYnBpbH(YYipD,NOlUp,AZCpR,kQsr) {" fullword ascii
    $s9  = "function rUJb(hWYMi,SNYAZ) {" fullword ascii
    $s10 = "function jEeoAUtt() {" fullword ascii
    $s11 = "function ExaJ(zPBmx) {" fullword ascii
    $s12 = "return oAYQW.status;" fullword ascii
    $s13 = "function hvxn(ubivO) {" fullword ascii
    $s14 = "function SIfJmPw(jNfN) {" fullword ascii
    $s15 = "RAF = a; break; " fullword ascii
    $s16 = "function fOxd(EOJFc) {" fullword ascii
    $s17 = "function pQFxPUdp(LHg) {" fullword ascii
    $s18 = "if (p >= rkKIE.length) {break;}" fullword ascii
    $s19 = "if (ubivO > 157643-727){return true;} else {return false;}" fullword ascii
    $s20 = "if (((new Date())>0,7759020888)) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}