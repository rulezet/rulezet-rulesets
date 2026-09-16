rule sig_20160321_442dc99fbd88f7cd81acc7434cbbf140 {
  meta:
    description = "datamaliciousorder - file 20160321_442dc99fbd88f7cd81acc7434cbbf140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11a5c8ec60df3a3f620904fdcd99f11311d98337aacff69ae576982df4237fb3"

  strings:
    $s1  = "return WScript.CreateObject(WRjtx);" fullword ascii
    $s2  = "var Th = true  , FwNP = aiU[7] + aiU[9] + aiU[11];" fullword ascii
    $s3  = "return lNYAmPS[0] + lNYAmPS[2] + lNYAmPS[4] + \".F\" + lNYAmPS[7] + lNYAmPS[9] + lNYAmPS[12] + lNYAmPS[14];" fullword ascii
    $s4  = "var lNYAmPS = BxiAW(nxLQklicJp+\" \"+\"System QM pvTLU Obj PGztbx ect HtDBGfK IwLBc\", \" \");" fullword ascii
    $s5  = "var aiU = (\"2.XMLHTTP VtiNeum WVTwt XML ream St mFlXizzE AD IhBvyal O EHhB D\").split(\" \");" fullword ascii
    $s6  = "kwNDJ.open(YIbDD,PyHrS,false);" fullword ascii
    $s7  = "function zxgn(kwNDJ,PyHrS,YIbDD) {" fullword ascii
    $s8  = "function kcrP(NuJQY,lFYlZ) {" fullword ascii
    $s9  = "return gRPBg;" fullword ascii
    $s10 = "if(e>=x.length) {break;}" fullword ascii
    $s11 = "function xFxFUIiPq(DwEWM) {" fullword ascii
    $s12 = "function MhNG(JtUMk) {" fullword ascii
    $s13 = "function wswK(KOxHp) {" fullword ascii
    $s14 = "function AFSqmFJFw(ogSJnVYGZSc) {" fullword ascii
    $s15 = "return kpJU[vsQyfN[0]];" fullword ascii
    $s16 = "if (orcnZ == 623-423){return true;} else {return false;}" fullword ascii
    $s17 = "return new ActiveXObject(rsjLAX);" fullword ascii
    $s18 = "return JtUMk.status;" fullword ascii
    $s19 = "function DDno(DCgfL,JEECM) {" fullword ascii
    $s20 = "return ALf.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}