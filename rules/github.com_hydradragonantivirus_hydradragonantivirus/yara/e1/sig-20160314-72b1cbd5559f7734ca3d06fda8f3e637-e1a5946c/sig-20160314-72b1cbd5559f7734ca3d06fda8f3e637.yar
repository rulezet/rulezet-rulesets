rule sig_20160314_72b1cbd5559f7734ca3d06fda8f3e637 {
  meta:
    description = "datamaliciousorder - file 20160314_72b1cbd5559f7734ca3d06fda8f3e637.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e0e0f32feede3f0ec5917f19cc714025e21b2f07af1d4024d6a1c65fb699d36"

  strings:
    $s1  = "return ejogSAL[0] + ejogSAL[2] + ejogSAL[4] + \".F\" + ejogSAL[7] + ejogSAL[9] + ejogSAL[12] + ejogSAL[14];" fullword ascii
    $s2  = "var Ov = true  , JxUi = eqW[7] + eqW[9] + eqW[11];" fullword ascii
    $s3  = "var ejogSAL = \"Sc OrDevTD r yBxyAmrlE ipting GdwCdcM Qiw ile XjteRkVdotsPha System oB cSwOa Obj zFRoFd ect IzbwymO LrqVZ\".spli" ascii
    $s4  = "var eqW = (\"2.XMLHTTP EtqJOTi cGukS XML ream St ZTuBGsWa AD MjPTppV O BkJb D\").split(\" \");" fullword ascii
    $s5  = "WoDNf.open(aqVCg,BNzal,false);" fullword ascii
    $s6  = "var ejogSAL = \"Sc OrDevTD r yBxyAmrlE ipting GdwCdcM Qiw ile XjteRkVdotsPha System oB cSwOa Obj zFRoFd ect IzbwymO LrqVZ\".spli" ascii
    $s7  = "pQB = r; break; " fullword ascii
    $s8  = "return OMiO.responseBody;" fullword ascii
    $s9  = "function Sohfkxw(OMiO) {" fullword ascii
    $s10 = "function JZSNH(BLNDHO) {" fullword ascii
    $s11 = "return new ActiveXObject(BLNDHO);" fullword ascii
    $s12 = "if (sSnzy > 154527-581){return true;} else {return false;}" fullword ascii
    $s13 = "function zjpfwmbaJ(aElQeXkOJOL) {" fullword ascii
    $s14 = "function ttXlQLzK(pUa) {" fullword ascii
    $s15 = "function CBVX(FNZFg,YorYc) {" fullword ascii
    $s16 = "return dRve.ExpandEnvironmentStrings(cSLJr);" fullword ascii
    $s17 = "function eXPd(SrXQa) {" fullword ascii
    $s18 = "function wNKT(DRryZ) {" fullword ascii
    $s19 = "return pUa.size;" fullword ascii
    $s20 = "function ImRy(rFpYw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}