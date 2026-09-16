rule sig_20160531_e6eced640e947245c3399aec09727228 {
  meta:
    description = "datamaliciousorder - file 20160531_e6eced640e947245c3399aec09727228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8983f6277977129f0868446c824532b6e64b1b73371c1dd4b79c619c63fa583c"

  strings:
    $s1  = "var fFLMES=function(){return WScript.CreateObject(tBFIYmuxgNKSUqyCRxh[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ExQYtRlirwVpMGUnmMPDAS(veBonX,tarsCtvkZjNvjVCWskDY){return veBonX.charAt(tarsCtvkZjNvjVCWskDY);}" fullword ascii
    $s3  = "function VLksJGJj(SEuXiZnwBsizd) {var KMjBNImhTZdkUbfyq = iEwkMmjDaDxxMJAcDwHJU.join(tBFIYmuxgNKSUqyCRxh[7]);var szArcgnApJrqV, " ascii
    $s4  = "function zrGdtVF(){return fFLMES.ExpandEnvironmentStrings(qQvosl())}" fullword ascii
    $s5  = "gnApJrqV, SiiIqjM, YuiQIDOQuKBYMvIHN);} while (RSioCpaxvR < SEuXiZnwBsizd.length);return myqKJEpOgAkAC;}" fullword ascii
    $s6  = "function VpELozooFtJZn(lkGfGsAQZ,aKUofwsudPZHG,dTIPdBUh){KIUCL=lkGfGsAQZ.split(dTIPdBUh);ogjyomVlK = tBFIYmuxgNKSUqyCRxh[0];for(" ascii
    $s7  = "function KiwcxBvhgEh(WXsBHemtzwWPNDZqIQ,YRtkZUKRkZNZYbvVpM){return WXsBHemtzwWPNDZqIQ.indexOf(YRtkZUKRkZNZYbvVpM);}" fullword ascii
    $s8  = "function VLksJGJj(SEuXiZnwBsizd) {var KMjBNImhTZdkUbfyq = iEwkMmjDaDxxMJAcDwHJU.join(tBFIYmuxgNKSUqyCRxh[7]);var szArcgnApJrqV, " ascii
    $s9  = "function x(NGOyazlxODxzoxygpUDy){return String.fromCharCode(NGOyazlxODxzoxygpUDy);}" fullword ascii
    $s10 = "function Jbibs(){return VpELozooFtJZn(tBFIYmuxgNKSUqyCRxh[11],[2,4,8,10],tBFIYmuxgNKSUqyCRxh[12]);}" fullword ascii
    $s11 = "(LbHYikGiBB,0x1,0x0)}function bxPtUoJgsuFFjk(ZQDZHWFJc,tKzOnlxRPqLFZ,lXzwTeLeIu){var RGdsv=ZQDZHWFJc.createtextfile(tKzOnlxRPqLF" ascii
    $s12 = "function QMggG(){return VpELozooFtJZn(tBFIYmuxgNKSUqyCRxh[13],[0,3,6],tBFIYmuxgNKSUqyCRxh[14]);}" fullword ascii
    $s13 = "V);else if (rBXHRKkUczwXXB == 64) myqKJEpOgAkAC += ueOygR(szArcgnApJrqV, SiiIqjM);else myqKJEpOgAkAC += quWtbCcXtkrWJqHqTj(szArc" ascii
    $s14 = "bXtWcdYQFoZ=0;bXtWcdYQFoZ<aKUofwsudPZHG.length;bXtWcdYQFoZ++) {ogjyomVlK+=KIUCL[aKUofwsudPZHG[bXtWcdYQFoZ]];}return ogjyomVlK.su" ascii
    $s15 = "function quWtbCcXtkrWJqHqTj(fPwsdLrNke,ycHRbxafbmdMoM,gSvsaR){return String.fromCharCode(fPwsdLrNke,ycHRbxafbmdMoM,gSvsaR);}" fullword ascii
    $s16 = "izd,RSioCpaxvR++));SOFllAsdlmPfqcKtPbgW = KiwcxBvhgEh(KMjBNImhTZdkUbfyq,ExQYtRlirwVpMGUnmMPDAS(SEuXiZnwBsizd,RSioCpaxvR++));soMA" ascii
    $s17 = "function VpELozooFtJZn(lkGfGsAQZ,aKUofwsudPZHG,dTIPdBUh){KIUCL=lkGfGsAQZ.split(dTIPdBUh);ogjyomVlK = tBFIYmuxgNKSUqyCRxh[0];for(" ascii
    $s18 = "function kcExhIE(QoRqTOnzzl,LbHYikGiBB) {var kscLCSw=[tBFIYmuxgNKSUqyCRxh[15]];QoRqTOnzzl[kscLCSw[0]]" fullword ascii
    $s19 = "(LbHYikGiBB,0x1,0x0)}function bxPtUoJgsuFFjk(ZQDZHWFJc,tKzOnlxRPqLFZ,lXzwTeLeIu){var RGdsv=ZQDZHWFJc.createtextfile(tKzOnlxRPqLF" ascii
    $s20 = "var gMvqAsVA=function(){return new ActiveXObject(tBFIYmuxgNKSUqyCRxh[1]);}();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}