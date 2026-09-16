rule sig_20151217_43575c487db4c0fe2ed324bcf53271c6 {
  meta:
    description = "datamaliciousorder - file 20151217_43575c487db4c0fe2ed324bcf53271c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5697d372e0baada7da1c7e8bbbee7657a43a1897303a960dfcc26d6d87205462"

  strings:
    $s1  = "function gwtivNCTRHdJCLqVt(KDgWa){bqMhpeAemlH= '';lDoqClLipfg=Math.round((Math.pow(Math.sin(486), 2) + Math.pow(Math.cos(486), 2" ascii
    $s2  = "GVNnrMHTMCXDNzwpDlljbQkUFkyeOEAwkuB([KDgWa[lDoqClLipfg][hKquZxTwI[lDoqClLipfg]]], Math.round((Math.pow(Math.sin(411), 2) + Math." ascii
    $s3  = "pow(Math.cos(411), 2) - 1)));} hKquZxTwI[lDoqClLipfg]++;}lDoqClLipfg++;} return bqMhpeAemlH}" fullword ascii
    $s4  = ") - 1));while(true){if (lDoqClLipfg >= (2577+33)/435){break;}hKquZxTwI[lDoqClLipfg]=Math.round((Math.pow(Math.sin(117), 2) + Mat" ascii
    $s5  = "h.pow(Math.cos(117), 2) - 1)); while(true) { if(hKquZxTwI[lDoqClLipfg] > KDgWa[lDoqClLipfg].length-(-459+619)/160) { break; } if" ascii
    $s6  = "function gwtivNCTRHdJCLqVt(KDgWa){bqMhpeAemlH= '';lDoqClLipfg=Math.round((Math.pow(Math.sin(486), 2) + Math.pow(Math.cos(486), 2" ascii
    $s7  = "function vDYfIqozmuIpLuCmftfGVNnrMHTMCXDNzwpDlljbQkUFkyeOEAwkuB(EhXcTcNwbuUOL,eGVWZmDCytgvbg){ return aHdbaTy[amJijoiq[xNntC(EhX" ascii
    $s8  = "function vDYfIqozmuIpLuCmftfGVNnrMHTMCXDNzwpDlljbQkUFkyeOEAwkuB(EhXcTcNwbuUOL,eGVWZmDCytgvbg){ return aHdbaTy[amJijoiq[xNntC(EhX" ascii
    $s9  = "function pYwPmYZ(fSlreyvoaPmobGKLUepAskzeztVlqZXDngWI) {return !pAWKryRrlTa(PMYtAvOAzMmFRzK(fSlreyvoaPmobGKLUepAskzeztVlqZXDngWI" ascii
    $s10 = "function pEvexTXpECEHiqu(UJAinriRxRDCXSnFs,kjoIdkaoXPGoVduISbBBSJavzZTYXYngua,GMcORnBMccJOVEEkjVoldVvKHNLcDcqImDM){eval(UJAinriR" ascii
    $s11 = "I);return VyfUQ;}" fullword ascii
    $s12 = "function pYwPmYZ(fSlreyvoaPmobGKLUepAskzeztVlqZXDngWI) {return !pAWKryRrlTa(PMYtAvOAzMmFRzK(fSlreyvoaPmobGKLUepAskzeztVlqZXDngWI" ascii
    $s13 = "function PMYtAvOAzMmFRzK(RgKApDpxEuCqCzkJeSp) {return parseFloat(RgKApDpxEuCqCzkJeSp);}" fullword ascii
    $s14 = "function pAWKryRrlTa(ijeZkLWwmyhhLu) {return isNaN(ijeZkLWwmyhhLu);}" fullword ascii
    $s15 = "function Z(sWABGNEpwDQLDv,DOlnWcEcPbZyz,rpWIYbQHzdB) {sWABGNEpwDQLDv[DOlnWcEcPbZyz]=rpWIYbQHzdB;}" fullword ascii
    $s16 = "function xNntC(juqlYUReGAf,LVWVrKtZgpMpm,axTfuRsI){oLNW=XFLuMJVDoGvWThBfG(juqlYUReGAf,LVWVrKtZgpMpm);VyfUQ=oLNW.toString(axTfuRs" ascii
    $s17 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s18 = "function XFLuMJVDoGvWThBfG(RPEGHNGJiS,lnWEpxNQTU) {return parseInt(RPEGHNGJiS,lnWEpxNQTU);}" fullword ascii
    $s19 = "function xNntC(juqlYUReGAf,LVWVrKtZgpMpm,axTfuRsI){oLNW=XFLuMJVDoGvWThBfG(juqlYUReGAf,LVWVrKtZgpMpm);VyfUQ=oLNW.toString(axTfuRs" ascii
    $s20 = "function K(WgtddiIRUSHR,qHryIIVbrZENoh){WgtddiIRUSHR.push(qHryIIVbrZENoh);}" fullword ascii

  condition:
    uint16(0) == 0x6d61 and
    8 of them
}