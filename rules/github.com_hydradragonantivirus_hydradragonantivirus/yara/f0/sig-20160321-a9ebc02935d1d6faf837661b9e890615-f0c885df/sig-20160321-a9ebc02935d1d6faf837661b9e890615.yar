rule sig_20160321_a9ebc02935d1d6faf837661b9e890615 {
  meta:
    description = "datamaliciousorder - file 20160321_a9ebc02935d1d6faf837661b9e890615.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a501fa060e0c2255a364fb1d0c316165b73326463f43602923bc1b2e5b5627b5"

  strings:
    $s1  = "return WScript.CreateObject(tnjFF);" fullword ascii
    $s2  = "function QfLPbvX(dLLP,LBVok) {" fullword ascii
    $s3  = "function OPCh(GGetP,kduyi) {" fullword ascii
    $s4  = "return dLLP.ExpandEnvironmentStrings(LBVok);" fullword ascii
    $s5  = "return IJRtszb[0] + IJRtszb[2] + IJRtszb[4] + \".F\" + IJRtszb[7] + IJRtszb[9] + IJRtszb[12] + IJRtszb[14];" fullword ascii
    $s6  = "var VL = true  , MygQ = tHt[7] + tHt[9] + tHt[11];" fullword ascii
    $s7  = "var tHt = (\"2.XMLHTTP tRXbdhP tKdYH XML ream St QEuePnyp AD XNfUjwD O lpXg D\").split(\" \");" fullword ascii
    $s8  = "weAwu.open(rdAQY,YLkoD,false);" fullword ascii
    $s9  = "var IJRtszb = YqGZK(qKDxpXSIyi+\" \"+\"System uv aAeJF Obj QiaYMG ect osXADgN Uctfj\", \" \");" fullword ascii
    $s10 = "return FuKzt.status;" fullword ascii
    $s11 = "function xYiA(Hweyn) {" fullword ascii
    $s12 = "return QfLPbvX(rA,ZEnNB[601-595]+ZEnNB[799-792]+ZEnNB[442-434]);" fullword ascii
    $s13 = "function uMvkiKWTz(MHCUH) {" fullword ascii
    $s14 = "function cmsZrzd(hZgM) {" fullword ascii
    $s15 = "function ZLiA(hTAZd,UbVti) {" fullword ascii
    $s16 = "if (uxWrS == 990-790){return true;} else {return false;}" fullword ascii
    $s17 = "return hZgM[fkmQUk[0]];" fullword ascii
    $s18 = "function hJkp(tnjFF) {" fullword ascii
    $s19 = "function aArPC(TYEbgT) {" fullword ascii
    $s20 = "function CKng(MidAq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}