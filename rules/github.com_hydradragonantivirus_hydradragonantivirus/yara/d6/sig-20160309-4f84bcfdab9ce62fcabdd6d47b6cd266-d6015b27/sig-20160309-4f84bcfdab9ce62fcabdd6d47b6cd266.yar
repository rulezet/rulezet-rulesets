rule sig_20160309_4f84bcfdab9ce62fcabdd6d47b6cd266 {
  meta:
    description = "datamaliciousorder - file 20160309_4f84bcfdab9ce62fcabdd6d47b6cd266.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a484cd44663c207ddbbcbe1ec51010fa53fc1276982ee9007851b6e13d5b1a6"

  strings:
    $s1  = "return xNuUtfu[0] + xNuUtfu[2] + xNuUtfu[4] + \".F\" + xNuUtfu[7] + xNuUtfu[9] + xNuUtfu[12] + xNuUtfu[14];" fullword ascii
    $s2  = "var rv = true  , eiVl = AQz[7] + AQz[9] + AQz[11];" fullword ascii
    $s3  = "var AQz = (\"2.XMLHTTP sxEhsYo Zjcxc XML ream St ZKdTkfYu AD iaMTFqf O qwfb D\").split(\" \");" fullword ascii
    $s4  = "PZhKQ.open(uinWl,hxojR,false);" fullword ascii
    $s5  = "function UBiXlaaNS(kdLGq,qCpIE,ZcmDo,oHKc) {" fullword ascii
    $s6  = "var xNuUtfu = \"Sc ItfgEVs r GmZBhlNXk ipting yBIpWFX kZu ile vnuopjANjsaCTf System wZ pqzuy Obj ruSxQy ect aSzYrvw\".split(\" " ascii
    $s7  = "function qUja(PZhKQ,hxojR,uinWl) {" fullword ascii
    $s8  = "function vuxI(nlvhb,EzYDD) {" fullword ascii
    $s9  = "return MEJolAW" fullword ascii
    $s10 = "function HqxMUGLG(Nex) {" fullword ascii
    $s11 = "function KpdM(bXmGg) {" fullword ascii
    $s12 = "return pSOIgBh(Jr,Ctixq[539-533]+Ctixq[961-954]+Ctixq[376-368]);" fullword ascii
    $s13 = "function AyyY(crFTW) {" fullword ascii
    $s14 = "function dOvmXwoUS(mVWPWsUrExx) {" fullword ascii
    $s15 = "return HVhNW.status;" fullword ascii
    $s16 = "yDn = y; break; " fullword ascii
    $s17 = "function lYyx(pjELd) {" fullword ascii
    $s18 = "function cLlx(kdzHZ,KcnDM) {" fullword ascii
    $s19 = "return new ActiveXObject(MGSAVM);" fullword ascii
    $s20 = "function TKcq(KVgId) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}