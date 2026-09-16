rule sig_20160527_3e75da7b23432c952f57c7ed3210963d {
  meta:
    description = "datamaliciousorder - file 20160527_3e75da7b23432c952f57c7ed3210963d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b33544066bf0452189666031000fe14d7fbc2d5ee0e01f53c2a219e4e37cacf"

  strings:
    $s1  = "function lGAGK() {return WScript;}function KlyzzAo(){return FkIKWmIlIBO.ExpandEnvironmentStrings(NJZlFi())}" fullword ascii
    $s2  = "function spTmm(diMhRktpApp,FBFMa){return diMhRktpApp.charAt(FBFMa);}" fullword ascii
    $s3  = "function YBEHpvREo(rzOkklbfMbZnTOCsGRy,FrCPpoFhOJjyDjqAIhORW){return rzOkklbfMbZnTOCsGRy.indexOf(FrCPpoFhOJjyDjqAIhORW);}" fullword ascii
    $s4  = "hlqCzJzWy(KBJEcZNhwgaskOEAhHP, QUBlTVHGrVePRqgGTHZmLV, IaBQxOaN);} while (vdgMEgmfEWeWmacplYu < CKdsJQfpYAhmq.length);return uJD" ascii
    $s5  = "function twBCvhlqCzJzWy(PZwqrgurRCmkynbbwVIROK,WYbstWyELytGJ,NDIlhWXuyYkgHcxJ){return String.fromCharCode(PZwqrgurRCmkynbbwVIROK" ascii
    $s6  = "function UolVscTYIVNfpP(CKdsJQfpYAhmq) {var gKHergVRPDYZdqjRE = wgVus.join(lOojfXZvtQbc[6]);var KBJEcZNhwgaskOEAhHP, QUBlTVHGrVe" ascii
    $s7  = "function DEayNKuerz(){return zjGfPqdLyBMIpn(lOojfXZvtQbc[10],[2,4,8,10],lOojfXZvtQbc[11]);}" fullword ascii
    $s8  = "de(92)+lOojfXZvtQbc[4],true);" fullword ascii
    $s9  = "var FwOdiIilEa=function(){return new ActiveXObject(lOojfXZvtQbc[0]);}();" fullword ascii
    $s10 = "function lgGHpYZTdZTwq(ANOGn,IRyGw) {var EpZNTptaZ=[lOojfXZvtQbc[15]];ANOGn[EpZNTptaZ[0]](IRyGw,0x1,0x0)}" fullword ascii
    $s11 = "function UolVscTYIVNfpP(CKdsJQfpYAhmq) {var gKHergVRPDYZdqjRE = wgVus.join(lOojfXZvtQbc[6]);var KBJEcZNhwgaskOEAhHP, QUBlTVHGrVe" ascii
    $s12 = "function QafnMsB(EIrSssbstXtpyuZXJtCePD,HQSPaTJUQQZ){return String.fromCharCode(EIrSssbstXtpyuZXJtCePD,HQSPaTJUQQZ);}" fullword ascii
    $s13 = "function xy(tLEQDgPuGjuncPo){return String.fromCharCode(tLEQDgPuGjuncPo);}" fullword ascii
    $s14 = "function NJZlFi(){return zjGfPqdLyBMIpn(lOojfXZvtQbc[8],[1,5,7],lOojfXZvtQbc[9]);}" fullword ascii
    $s15 = "function zjGfPqdLyBMIpn(sOiAfX,YMPxpYSlJSfDBg,lxmDmSxAXy){seAlYcgUT=sOiAfX.split(lxmDmSxAXy);lLSTsh = lOojfXZvtQbc[14];for(zBWEq" ascii
    $s16 = "function sCEkIQt(){return zjGfPqdLyBMIpn(lOojfXZvtQbc[12],[0,3,6],lOojfXZvtQbc[13]);}" fullword ascii
    $s17 = "QclR=0;zBWEqQclR<YMPxpYSlJSfDBg.length;zBWEqQclR++) {lLSTsh+=seAlYcgUT[YMPxpYSlJSfDBg[zBWEqQclR]];}return lLSTsh.substring(3,lLS" ascii
    $s18 = "var FkIKWmIlIBO=function(){return lGAGK().CreateObject(lOojfXZvtQbc[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s19 = "function twBCvhlqCzJzWy(PZwqrgurRCmkynbbwVIROK,WYbstWyELytGJ,NDIlhWXuyYkgHcxJ){return String.fromCharCode(PZwqrgurRCmkynbbwVIROK" ascii
    $s20 = "var MxzmVkHh = FwOdiIilEa.createtextfile(FkIKWmIlIBO.ExpandEnvironmentStrings(lOojfXZvtQbc[2]+lOojfXZvtQbc[3])+String.fromCharCo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}