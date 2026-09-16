rule sig_20151217_a8508397d63388dcbc3685d419f2b62d {
  meta:
    description = "datamaliciousorder - file 20151217_a8508397d63388dcbc3685d419f2b62d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05bd6c816e83a00223556ac06de9ff912c3bd8effaf4946b9e806e757b39ff39"

  strings:
    $s1  = "Math.cos(496), 2) - 1)));} rLYsYFtWj[vcwqDRHwcbT]++;}vcwqDRHwcbT++;} return ADlhDyVPfKS}" fullword ascii
    $s2  = "pow(Math.cos(767), 2) - 1)); while(true) { if(rLYsYFtWj[vcwqDRHwcbT] > XXHgn[vcwqDRHwcbT].length-(-124+642)/518) { break; } if (" ascii
    $s3  = "function WLOnwsrnxPvWrBVJT(XXHgn){ADlhDyVPfKS= '';vcwqDRHwcbT=Math.round((Math.pow(Math.sin(32), 2) + Math.pow(Math.cos(32), 2) " ascii
    $s4  = "- 1));while(true){if (vcwqDRHwcbT >= (3112+92)/534){break;}rLYsYFtWj[vcwqDRHwcbT]=Math.round((Math.pow(Math.sin(767), 2) + Math." ascii
    $s5  = "function WLOnwsrnxPvWrBVJT(XXHgn){ADlhDyVPfKS= '';vcwqDRHwcbT=Math.round((Math.pow(Math.sin(32), 2) + Math.pow(Math.cos(32), 2) " ascii
    $s6  = "function NhYToOR(WonpkPJdeIaPsJSGPvfEfgfvwJsOozVtQiiU) {return !JqwlIcMzGbS(mmSRtNDJuHGYIQv(WonpkPJdeIaPsJSGPvfEfgfvwJsOozVtQiiU" ascii
    $s7  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s8  = "function JqwlIcMzGbS(LKCqeefgwjtKCk) {return isNaN(LKCqeefgwjtKCk);}" fullword ascii
    $s9  = "function X(SmNvYornfHCzTD,FmUjfjTNbPKwB,bBSNJKUhicQ) {SmNvYornfHCzTD[FmUjfjTNbPKwB]=bBSNJKUhicQ;}" fullword ascii
    $s10 = ",'$','F','/','D','W','q','c','H','b','X','u','2','M','x','i','D','5','0','Y','x','v','y','1','Z','J','1','m','[','j','5',String." ascii
    $s11 = "function UWnTLeNRSmXNfWW(teOSzVaYgFxjsmaxJ,ZKOGIQUfcELaDGLuDuXfHuCvugmtJvxdNu,xnLhppvrJrxhhNkYYTlQzstjfYlGziCLtDG){eval(teOSzVaY" ascii
    $s12 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s13 = "function UWnTLeNRSmXNfWW(teOSzVaYgFxjsmaxJ,ZKOGIQUfcELaDGLuDuXfHuCvugmtJvxdNu,xnLhppvrJrxhhNkYYTlQzstjfYlGziCLtDG){eval(teOSzVaY" ascii
    $s14 = "function JpZCNOCtGzGIYOzlFOgYukaXYYIGmPmDsHBEKprtqnFclwckkASJfy(XqOpCMtcbqGZq,dWLaYqCWvkorWT){ return lOOybRP[CzhRpsUJ[XjaKp(XqO" ascii
    $s15 = "function NhYToOR(WonpkPJdeIaPsJSGPvfEfgfvwJsOozVtQiiU) {return !JqwlIcMzGbS(mmSRtNDJuHGYIQv(WonpkPJdeIaPsJSGPvfEfgfvwJsOozVtQiiU" ascii
    $s16 = "function YRMHbRjOPXUuQBMiO(vfriWOcHII,DDiAqrEiHH) {return parseInt(vfriWOcHII,DDiAqrEiHH);}" fullword ascii
    $s17 = "function YUBbUlGKvifz(rgjjEnfyKlLRS) {return isFinite(rgjjEnfyKlLRS);}" fullword ascii
    $s18 = "function JpZCNOCtGzGIYOzlFOgYukaXYYIGmPmDsHBEKprtqnFclwckkASJfy(XqOpCMtcbqGZq,dWLaYqCWvkorWT){ return lOOybRP[CzhRpsUJ[XjaKp(XqO" ascii
    $s19 = "W);return oWyrC;}" fullword ascii
    $s20 = "function c(oKgncIuxsgDU,ymtQPCSwGLltkU){oKgncIuxsgDU.push(ymtQPCSwGLltkU);}" fullword ascii

  condition:
    uint16(0) == 0x7a43 and
    8 of them
}