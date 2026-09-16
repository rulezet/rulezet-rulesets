rule sig_20151217_c0d9e43ff730ae72d21f2fa67b6095e1 {
  meta:
    description = "datamaliciousorder - file 20151217_c0d9e43ff730ae72d21f2fa67b6095e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1f3a61087832d5e85b7db91e169b7ebc31c26c42ea128596dadba42bb75fa61"

  strings:
    $s1  = "ath.cos(906), 2) - 1)));} ZEPgrmsSg[BZUmqMmZOxl]++;}BZUmqMmZOxl++;} return oPeHZaWiFNC}" fullword ascii
    $s2  = ".pow(Math.cos(401), 2) - 1)); while(true) { if(ZEPgrmsSg[BZUmqMmZOxl] > dRKop[BZUmqMmZOxl].length-(-98+668)/570) { break; } if (" ascii
    $s3  = "function ixaBuUucQQXHsUanc(dRKop){oPeHZaWiFNC= '';BZUmqMmZOxl=Math.round((Math.pow(Math.sin(69), 2) + Math.pow(Math.cos(69), 2) " ascii
    $s4  = "- 1));while(true){if (BZUmqMmZOxl >= (4639+743)/897){break;}ZEPgrmsSg[BZUmqMmZOxl]=Math.round((Math.pow(Math.sin(401), 2) + Math" ascii
    $s5  = "function ixaBuUucQQXHsUanc(dRKop){oPeHZaWiFNC= '';BZUmqMmZOxl=Math.round((Math.pow(Math.sin(69), 2) + Math.pow(Math.cos(69), 2) " ascii
    $s6  = "function NYdjb(WplaKfTPfqP,GdQRtSGoUacNZ,xULeLuVI){tQMA=xtsKgOJUCilrxtFDu(WplaKfTPfqP,GdQRtSGoUacNZ);xKEqt=tQMA.toString(xULeLuV" ascii
    $s7  = "function NYdjb(WplaKfTPfqP,GdQRtSGoUacNZ,xULeLuVI){tQMA=xtsKgOJUCilrxtFDu(WplaKfTPfqP,GdQRtSGoUacNZ);xKEqt=tQMA.toString(xULeLuV" ascii
    $s8  = "function xVjZIoi(ypFXGKzgNLamieMKBJKWXxudcQVcpmRzrXUy) {return !MNycDOtqDPw(bwKfipEUpBMTXFP(ypFXGKzgNLamieMKBJKWXxudcQVcpmRzrXUy" ascii
    $s9  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s10 = "function upYojHIJQRFRExJkQdZsvJzfbKkURdrfukFEsYGfmmPkDCsyZRzbvE(eqDOqRqMLlKgN,JhZwYpTPMMVhUU){ return jhnRFTE[gPLUxBsG[NYdjb(eqD" ascii
    $s11 = "function xtsKgOJUCilrxtFDu(PTmssTRMWS,qVlCnuiaTH) {return parseInt(PTmssTRMWS,qVlCnuiaTH);}" fullword ascii
    $s12 = "function upYojHIJQRFRExJkQdZsvJzfbKkURdrfukFEsYGfmmPkDCsyZRzbvE(eqDOqRqMLlKgN,JhZwYpTPMMVhUU){ return jhnRFTE[gPLUxBsG[NYdjb(eqD" ascii
    $s13 = ",'V','P','7','6','P','W','D','(','I','O','M','X','A','/','H','Y','.',':','p','h','(','s','Z','W','r','{','[','0','/','L',String." ascii
    $s14 = "function LIFiaoWWzxJj(JZRfgBlDfIFfa) {return isFinite(JZRfgBlDfIFfa);}" fullword ascii
    $s15 = "function f(MwPwhlDnrDglcw,iBOrXeUVIQlIU,jkpyapIHtkU) {MwPwhlDnrDglcw[iBOrXeUVIQlIU]=jkpyapIHtkU;}" fullword ascii
    $s16 = "I);return xKEqt;}" fullword ascii
    $s17 = "function xVjZIoi(ypFXGKzgNLamieMKBJKWXxudcQVcpmRzrXUy) {return !MNycDOtqDPw(bwKfipEUpBMTXFP(ypFXGKzgNLamieMKBJKWXxudcQVcpmRzrXUy" ascii
    $s18 = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s19 = "function MNycDOtqDPw(sAJzWUfEFdssnU) {return isNaN(sAJzWUfEFdssnU);}" fullword ascii
    $s20 = "function t(vQmKHWzKvjcm,sqwjgyUuquQiXa){vQmKHWzKvjcm.push(sqwjgyUuquQiXa);}" fullword ascii

  condition:
    uint16(0) == 0x5067 and
    8 of them
}