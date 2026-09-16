rule sig_20160303_39a6163fed505f891875b627969f7b1f {
  meta:
    description = "datamaliciousorder - file 20160303_39a6163fed505f891875b627969f7b1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e1dc05fb7b10166c96fcdcd5d25fc076fba88e92c1c0873e9324bbbd4bb7880"

  strings:
    $s1  = "var bpuAf = \"gniByb jZi pt.Shell jVEQvYX Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var cb = true  , Lzhn = WLH[7] + \"\" + WLH[9];" fullword ascii
    $s3  = "return wPHmsZG[0] + wPHmsZG[2] + wPHmsZG[4] + \".F\" + wPHmsZG[7] + wPHmsZG[9] + wPHmsZG[12] + wPHmsZG[14];" fullword ascii
    $s4  = "var WLH = (vVw + \"TTP\" + \" WejfIEP wqdYs XML ream St tEuDlubD AD lWZfQGG OD\").split(\" \");" fullword ascii
    $s5  = "var wPHmsZG = \"Sc vSnIMCL r OEPPAKwlP ipting QnQJMFm LpK ile SpJJSHvdQPqAXF System ms Zxskl Obj ggTpJG ect LFotiLd\".split(\" " ascii
    $s6  = "wDHRB.open(XpFyn,yUlLM,false);" fullword ascii
    $s7  = "function RElVTVo(DndT) {" fullword ascii
    $s8  = "function NAxU(IQkhS) {" fullword ascii
    $s9  = "return JevDhAf" fullword ascii
    $s10 = "if (IQkhS > 192832-439){return true;} else {return false;}" fullword ascii
    $s11 = "function MvoyGXg(nNqT) {" fullword ascii
    $s12 = "function RSix(tyxXT) {" fullword ascii
    $s13 = "function WtnY(kQzQv) {" fullword ascii
    $s14 = "function vnBu(apVCb,nHTYX) {" fullword ascii
    $s15 = "return new ActiveXObject(tbAxDD);" fullword ascii
    $s16 = "return nf.ExpandEnvironmentStrings(bpuAf[6]);" fullword ascii
    $s17 = "function SBEg(SMozy,DWlbO) {" fullword ascii
    $s18 = "function YvsA(kCUDC) {" fullword ascii
    $s19 = "if (LEVXQ == 546-346){return true;} else {return false;}" fullword ascii
    $s20 = "pDM = o; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}