rule sig_20160323_c12b3ede3e6cd79aec4a2ee7f452985b {
  meta:
    description = "datamaliciousorder - file 20160323_c12b3ede3e6cd79aec4a2ee7f452985b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87fd223815f130ff338d4fba9f6c845d9d0696888dc2abd89b051b3264709da9"

  strings:
    $s1  = "return WScript.CreateObject(XJEEM);" fullword ascii
    $s2  = "return GlQCjnB[0] + GlQCjnB[2] + GlQCjnB[4] + \".F\" + GlQCjnB[7] + GlQCjnB[9] + GlQCjnB[12] + GlQCjnB[14];" fullword ascii
    $s3  = "var md = true  , yqOv = NBy[7] + NBy[9] + NBy[11];" fullword ascii
    $s4  = "var GlQCjnB = DvUvv(nMbzTwZibX+\" \"+\"System ww eshQA Obj tuKret ect YsILHNV raMLp\", \" \");" fullword ascii
    $s5  = "qyFD.open(Udjby,qbwDO,false);" fullword ascii
    $s6  = "var NBy = (\"2.XMLHTTP wCJtFED CYPiO XML ream St kngOPmvU AD izTWSoO O kNtE D\").split(\" \");" fullword ascii
    $s7  = "function sKeq(VNuZo) {" fullword ascii
    $s8  = "return XVEAmhc(Tr,pYNTH[207-201]+pYNTH[475-468]+pYNTH[578-570]);" fullword ascii
    $s9  = "function HjalhrCgr(CFgXzDyAkVs) {" fullword ascii
    $s10 = "function XVEAmhc(mfAQ,jvNjg) {" fullword ascii
    $s11 = "return aNw.size;" fullword ascii
    $s12 = "return ToJ.split(AcqxM);" fullword ascii
    $s13 = "function pzSl(fgTxZ) {" fullword ascii
    $s14 = "if(T>=K.length) {break;}" fullword ascii
    $s15 = "return KMcwS;" fullword ascii
    $s16 = "function sJtd(VGoKF,mbJKY) {" fullword ascii
    $s17 = "function aJCpj(gnnGzk) {" fullword ascii
    $s18 = "return mfAQ.ExpandEnvironmentStrings(jvNjg);" fullword ascii
    $s19 = "function iHBY(GQhOH,qbwDO,Udjby) {" fullword ascii
    $s20 = "return GPkn[KbpmTa[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}