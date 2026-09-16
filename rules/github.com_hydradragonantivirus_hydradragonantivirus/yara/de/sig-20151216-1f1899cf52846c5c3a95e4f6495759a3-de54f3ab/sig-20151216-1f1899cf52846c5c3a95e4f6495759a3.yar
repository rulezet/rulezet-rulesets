rule sig_20151216_1f1899cf52846c5c3a95e4f6495759a3 {
  meta:
    description = "datamaliciousorder - file 20151216_1f1899cf52846c5c3a95e4f6495759a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27828a7c810af54c7a17a22ca36c3b14e182653a2c6c5d76392aa6450f6f8ede"

  strings:
    $s1  = ") - 1));while(true){if (sGaCKsvUYVx >= (4452+288)/790){break;}yMaAMuXPg[sGaCKsvUYVx]=Math.round((Math.pow(Math.sin(119), 2) + Ma" ascii
    $s2  = "function XlksJwdoIgFiLPlyN(ZIoTM){CqMQLArnbPq= '';sGaCKsvUYVx=Math.round((Math.pow(Math.sin(486), 2) + Math.pow(Math.cos(486), 2" ascii
    $s3  = "w(Math.cos(357), 2) - 1)));} yMaAMuXPg[sGaCKsvUYVx]++;}sGaCKsvUYVx++;} return CqMQLArnbPq}" fullword ascii
    $s4  = "th.pow(Math.cos(119), 2) - 1)); while(true) { if(yMaAMuXPg[sGaCKsvUYVx] > ZIoTM[sGaCKsvUYVx].length-(200+91)/291) { break; } if " ascii
    $s5  = "function XlksJwdoIgFiLPlyN(ZIoTM){CqMQLArnbPq= '';sGaCKsvUYVx=Math.round((Math.pow(Math.sin(486), 2) + Math.pow(Math.cos(486), 2" ascii
    $s6  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s7  = "function MeQSnvlTyjVIChX(FZMZAuxqgznCrbvFJdO) {return parseFloat(FZMZAuxqgznCrbvFJdO);}" fullword ascii
    $s8  = "function IMFAi(RvNyOQTYEGO,IeQcUmKbJgbIW,CtlhzJUC){FTQq=MTQyBVELZZBrBLpSI(RvNyOQTYEGO,IeQcUmKbJgbIW);qyddr=FTQq.toString(CtlhzJU" ascii
    $s9  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s10 = "function IMFAi(RvNyOQTYEGO,IeQcUmKbJgbIW,CtlhzJUC){FTQq=MTQyBVELZZBrBLpSI(RvNyOQTYEGO,IeQcUmKbJgbIW);qyddr=FTQq.toString(CtlhzJU" ascii
    $s11 = "function g(xjUalutaxBeZ,IoQvZRgpaqTZeb){xjUalutaxBeZ.push(IoQvZRgpaqTZeb);}" fullword ascii
    $s12 = "function YtaMNpEItJmazOwsQAeUgaDgxDnnMpTulksuneHtWpfBNDFkyxIuhm(aLlMZwkUxCBgf,YYSNUokICDNZmx){ return Sehbuvu[zDmxSkKH[IMFAi(aLl" ascii
    $s13 = "function o(vMeFhLLAQfPqON,ksDkHpdWiFVIr,LqRSVSRkYUt) {vMeFhLLAQfPqON[ksDkHpdWiFVIr]=LqRSVSRkYUt;}" fullword ascii
    $s14 = "function GKbNZKcUJvIU(tNfVliSdocwyn) {return isFinite(tNfVliSdocwyn);}" fullword ascii
    $s15 = "function MTQyBVELZZBrBLpSI(jVWgyjVMek,vwgpVjjxlb) {return parseInt(jVWgyjVMek,vwgpVjjxlb);}" fullword ascii
    $s16 = "function shwzGLlBPci(KUQEoWEeMLCFLX) {return isNaN(KUQEoWEeMLCFLX);}" fullword ascii
    $s17 = "function YtaMNpEItJmazOwsQAeUgaDgxDnnMpTulksuneHtWpfBNDFkyxIuhm(aLlMZwkUxCBgf,YYSNUokICDNZmx){ return Sehbuvu[zDmxSkKH[IMFAi(aLl" ascii
    $s18 = "C);return qyddr;}" fullword ascii
    $s19 = "function ohPWSOV(HgOzpgxHGNCaUqzFUUwCjNzAFQNIHFrtJCHb) {return !shwzGLlBPci(MeQSnvlTyjVIChX(HgOzpgxHGNCaUqzFUUwCjNzAFQNIHFrtJCHb" ascii
    $s20 = "function KhjtHEoilCzowNk(fbIvECiqkyLeFyXBU,mDbrltNWIECkvFLtJhQkyTsKDHvjWWCAeH,IuYilaEWSzVveoYXenuhvufLeZdjJorpPwv){eval(fbIvECiq" ascii

  condition:
    uint16(0) == 0x447a and
    8 of them
}