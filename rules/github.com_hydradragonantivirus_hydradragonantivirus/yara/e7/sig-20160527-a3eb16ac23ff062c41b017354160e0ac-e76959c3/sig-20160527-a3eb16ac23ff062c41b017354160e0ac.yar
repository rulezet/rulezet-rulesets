rule sig_20160527_a3eb16ac23ff062c41b017354160e0ac {
  meta:
    description = "datamaliciousorder - file 20160527_a3eb16ac23ff062c41b017354160e0ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c4dd4146ebddc204f58897d1cca4ae0665a5600571412646f675fb6907ac592"

  strings:
    $s1  = "function TWoQHakkltunkV() {return WScript;}function DVvMrTHPJAkgot(){return fLSULJ.ExpandEnvironmentStrings(WPlQVEWO())}" fullword ascii
    $s2  = "function bAcjEyRspOL(PYBKxLlunROHL) {var uACBfl = CxFXPFelVHq.join(wxmUECrWFjR[6]);var MHydzTFhXzdLIFAoGWR, ZxNgKFmUugWVSQcWGa, " ascii
    $s3  = "function BRAveYF(nLcWpfdAXUuIFY,sSCoBOGJfMKTbL){return nLcWpfdAXUuIFY.charAt(sSCoBOGJfMKTbL);}" fullword ascii
    $s4  = "zTFhXzdLIFAoGWR, ZxNgKFmUugWVSQcWGa);else VaBckmMxmNiaq += GOsPZ(MHydzTFhXzdLIFAoGWR, ZxNgKFmUugWVSQcWGa, YBJxlYRSpyHeeFXqfrS);}" ascii
    $s5  = "function AijlXLFTrVsq(){return WQabZ(wxmUECrWFjR[12],[0,3,6],wxmUECrWFjR[13]);}" fullword ascii
    $s6  = "var fLSULJ=function(){return TWoQHakkltunkV().CreateObject(wxmUECrWFjR[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s7  = "function zrFtcYYJMoQC(){return WQabZ(wxmUECrWFjR[10],[2,4,8,10],wxmUECrWFjR[11]);}" fullword ascii
    $s8  = "function bAcjEyRspOL(PYBKxLlunROHL) {var uACBfl = CxFXPFelVHq.join(wxmUECrWFjR[6]);var MHydzTFhXzdLIFAoGWR, ZxNgKFmUugWVSQcWGa, " ascii
    $s9  = "function WQabZ(zRAWmN,suruv,umbEfbJqc){gFIgLoyeL=zRAWmN.split(umbEfbJqc);BjkRNcSpIhvrr = wxmUECrWFjR[14];for(aIPftQVz=0;aIPftQVz" ascii
    $s10 = "var OTXktzxBBvxMYg = VaFkxvNNLkVXLQ.createtextfile(fLSULJ.ExpandEnvironmentStrings(wxmUECrWFjR[2]+wxmUECrWFjR[3])+String.fromCha" ascii
    $s11 = "function WQabZ(zRAWmN,suruv,umbEfbJqc){gFIgLoyeL=zRAWmN.split(umbEfbJqc);BjkRNcSpIhvrr = wxmUECrWFjR[14];for(aIPftQVz=0;aIPftQVz" ascii
    $s12 = "rCode(92)+wxmUECrWFjR[4],true);" fullword ascii
    $s13 = "function WXlaqpsEEv(tMkwpDbUZ,RYMJIHiD) {var KkLcMJQc=[wxmUECrWFjR[15]];tMkwpDbUZ[KkLcMJQc[0]](RYMJIHiD,0x1,0x0)}" fullword ascii
    $s14 = "function WPlQVEWO(){return WQabZ(wxmUECrWFjR[8],[1,5,7],wxmUECrWFjR[9]);}" fullword ascii
    $s15 = "<suruv.length;aIPftQVz++) {BjkRNcSpIhvrr+=gFIgLoyeL[suruv[aIPftQVz]];}return BjkRNcSpIhvrr.substring(3,BjkRNcSpIhvrr.length);}" fullword ascii
    $s16 = " while (xdNGaaAANKb < PYBKxLlunROHL.length);return VaBckmMxmNiaq;}" fullword ascii
    $s17 = "function GOsPZ(IXIkzGJmGfbeK,yegtSomoMhCTKPBebpW,YreFtqcq){return String.fromCharCode(IXIkzGJmGfbeK,yegtSomoMhCTKPBebpW,YreFtqcq" ascii
    $s18 = "function CxTBhVYhNoXglZJ(KHAFHgABHKXSnKr,XxhOPWoqnyydGAW){return String.fromCharCode(KHAFHgABHKXSnKr,XxhOPWoqnyydGAW);}" fullword ascii
    $s19 = "xff;if (uGxcsZzF == 64) VaBckmMxmNiaq += G(MHydzTFhXzdLIFAoGWR);else if (vpoqYCQdvF == 64) VaBckmMxmNiaq += CxTBhVYhNoXglZJ(MHyd" ascii
    $s20 = "var VaFkxvNNLkVXLQ=function(){return new ActiveXObject(wxmUECrWFjR[0]);}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}