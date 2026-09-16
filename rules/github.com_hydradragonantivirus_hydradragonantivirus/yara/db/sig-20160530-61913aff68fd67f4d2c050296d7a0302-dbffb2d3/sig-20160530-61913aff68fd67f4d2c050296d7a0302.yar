rule sig_20160530_61913aff68fd67f4d2c050296d7a0302 {
  meta:
    description = "datamaliciousorder - file 20160530_61913aff68fd67f4d2c050296d7a0302.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59051c1c0917eb7a39e266f810361cceec146d8c2bfdca7d43ff90b72bf3270"

  strings:
    $s1  = "var fwKElCtiOtvA=function(){return WScript.CreateObject(KRXxPCNozScqL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WBahoREOZmpbGcw(SMbZrlBMennwQjoXrPxtH,qfIWqoGXCaEcmJJDzvM){return SMbZrlBMennwQjoXrPxtH.charAt(qfIWqoGXCaEcmJJDzvM);}" fullword ascii
    $s3  = "function afx(cqYCNRrxPydRjGy){return String.fromCharCode(cqYCNRrxPydRjGy);}" fullword ascii
    $s4  = " while (VQAqtvYjw < SGbEqJyYsQDxy.length);return FuPqBAjXjBMKFGzd;}" fullword ascii
    $s5  = "function HAVIuS(){return fwKElCtiOtvA.ExpandEnvironmentStrings(mixPsiWgGO())}" fullword ascii
    $s6  = "function ijDugxgVwJO(){return hBceXcsydtjbK(KRXxPCNozScqL[11],[2,4,8,10],KRXxPCNozScqL[12]);}" fullword ascii
    $s7  = "zd += uVZHCyCwCfxgOAdvE(YmEPSsNWkSdm, afdMtIBTwx);else FuPqBAjXjBMKFGzd += zUkEonOb(YmEPSsNWkSdm, afdMtIBTwx, IPNRXqAgvXgdhPC);}" ascii
    $s8  = "function uVZHCyCwCfxgOAdvE(TCVwmJvcSg,XXwoXpILwOZuZvt){return String.fromCharCode(TCVwmJvcSg,XXwoXpILwOZuZvt);}" fullword ascii
    $s9  = "function lnKMdQWd(uYnKhElaO,UAtvp) {var mFvJSK=[KRXxPCNozScqL[15]];uYnKhElaO[mFvJSK[0]]" fullword ascii
    $s10 = "function hBceXcsydtjbK(lspxOvXfA,ZqhPIYuqNwQEAT,WyNacla){rxZnhaCLDiiUG=lspxOvXfA.split(WyNacla);LUpAjkiJw = KRXxPCNozScqL[0];for" ascii
    $s11 = "var Vrkxd = VHMjpaQCr.createtextfile(fwKElCtiOtvA.ExpandEnvironmentStrings(KRXxPCNozScqL[3]+KRXxPCNozScqL[4])+String.fromCharCod" ascii
    $s12 = "function zUkEonOb(olZRRFzzLhLAVtw,AMmGLICcykwTGBDC,zYBowhDSXmYGOqRqhYIf){return String.fromCharCode(olZRRFzzLhLAVtw,AMmGLICcykwT" ascii
    $s13 = "function ybUeCyMGokHi(hcURHZSwCQTSHxIBOnJS,WUAimOCkzrydrwYGDXoNe){return hcURHZSwCQTSHxIBOnJS.indexOf(WUAimOCkzrydrwYGDXoNe);}" fullword ascii
    $s14 = "function GBAbHuLt(SGbEqJyYsQDxy) {var sNnsNAjYAHyKTvIg = POIdkK.join(KRXxPCNozScqL[7]);var YmEPSsNWkSdm, afdMtIBTwx, IPNRXqAgvXg" ascii
    $s15 = "(KuscBzL=0;KuscBzL<ZqhPIYuqNwQEAT.length;KuscBzL++) {LUpAjkiJw+=rxZnhaCLDiiUG[ZqhPIYuqNwQEAT[KuscBzL]];}return LUpAjkiJw.substri" ascii
    $s16 = "e(92)+KRXxPCNozScqL[5],true);" fullword ascii
    $s17 = "function zUkEonOb(olZRRFzzLhLAVtw,AMmGLICcykwTGBDC,zYBowhDSXmYGOqRqhYIf){return String.fromCharCode(olZRRFzzLhLAVtw,AMmGLICcykwT" ascii
    $s18 = "function mixPsiWgGO(){return hBceXcsydtjbK(KRXxPCNozScqL[9],[1,5,7],KRXxPCNozScqL[10]);}" fullword ascii
    $s19 = "function GBAbHuLt(SGbEqJyYsQDxy) {var sNnsNAjYAHyKTvIg = POIdkK.join(KRXxPCNozScqL[7]);var YmEPSsNWkSdm, afdMtIBTwx, IPNRXqAgvXg" ascii
    $s20 = "function hBceXcsydtjbK(lspxOvXfA,ZqhPIYuqNwQEAT,WyNacla){rxZnhaCLDiiUG=lspxOvXfA.split(WyNacla);LUpAjkiJw = KRXxPCNozScqL[0];for" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}