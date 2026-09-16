rule sig_20151217_bea0a1ea722c133912265f2590c36354 {
  meta:
    description = "datamaliciousorder - file 20151217_bea0a1ea722c133912265f2590c36354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82dcaffd908bc673bc72071338984be53bb49d8ee6b020b7190bcf13834a90c7"

  strings:
    $s1  = "th.pow(Math.cos(258), 2) - 1)); while(true) { if(eXjNtGFwS[sSijOncYabZ] > LsuzY[sSijOncYabZ].length-(-109+384)/275) { break; } i" ascii
    $s2  = ") - 1));while(true){if (sSijOncYabZ >= (1618+332)/325){break;}eXjNtGFwS[sSijOncYabZ]=Math.round((Math.pow(Math.sin(258), 2) + Ma" ascii
    $s3  = "function PXtiQKqRquGGqNsqW(LsuzY){gdxJqOCLnva= '';sSijOncYabZ=Math.round((Math.pow(Math.sin(772), 2) + Math.pow(Math.cos(772), 2" ascii
    $s4  = ".pow(Math.cos(894), 2) - 1)));} eXjNtGFwS[sSijOncYabZ]++;}sSijOncYabZ++;} return gdxJqOCLnva}" fullword ascii
    $s5  = "function PXtiQKqRquGGqNsqW(LsuzY){gdxJqOCLnva= '';sSijOncYabZ=Math.round((Math.pow(Math.sin(772), 2) + Math.pow(Math.cos(772), 2" ascii
    $s6  = "WwXtXaxnunvMCloUUqjHWuZyyMMHHxCiWtgB([LsuzY[sSijOncYabZ][eXjNtGFwS[sSijOncYabZ]]], Math.round((Math.pow(Math.sin(894), 2) + Math" ascii
    $s7  = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s8  = "function hLQxzwQjFhuy(eHyNhWxBwXlaz) {return isFinite(eHyNhWxBwXlaz);}" fullword ascii
    $s9  = "function wUTAJhJAugFmhae(eAUkkeeUeHRIfbkEf,WnsZIPrmenfqrUMNmMQwcgtoCSphYfzVhm,IGxShmmgxSXGnePivxCSaKnYqQhIQvhdOkC){eval(eAUkkeeU" ascii
    $s10 = "function wUTAJhJAugFmhae(eAUkkeeUeHRIfbkEf,WnsZIPrmenfqrUMNmMQwcgtoCSphYfzVhm,IGxShmmgxSXGnePivxCSaKnYqQhIQvhdOkC){eval(eAUkkeeU" ascii
    $s11 = "function KHGbvwhIbKEZZXwBi(JGmaodukua,nLRXVVXjti) {return parseInt(JGmaodukua,nLRXVVXjti);}" fullword ascii
    $s12 = "function uwaza(LpSphfTEnts,qSqNYnvOglnfT,KjuTWMJw){tsmU=KHGbvwhIbKEZZXwBi(LpSphfTEnts,qSqNYnvOglnfT);lUOZl=tsmU.toString(KjuTWMJ" ascii
    $s13 = "w);return lUOZl;}" fullword ascii
    $s14 = "function uwaza(LpSphfTEnts,qSqNYnvOglnfT,KjuTWMJw){tsmU=KHGbvwhIbKEZZXwBi(LpSphfTEnts,qSqNYnvOglnfT);lUOZl=tsmU.toString(KjuTWMJ" ascii
    $s15 = "function WpUxuuTrVELmbyj(GDuxOzsQXmfXznJfaGA) {return parseFloat(GDuxOzsQXmfXznJfaGA);}" fullword ascii
    $s16 = "function r(NcNEzRnsixIWWw,vXcyKDDJdNatq,YfCBCdrhgaH) {NcNEzRnsixIWWw[vXcyKDDJdNatq]=YfCBCdrhgaH;}" fullword ascii
    $s17 = "function k(IyeMQMRRWmiL,qLmruCVBbFQbWu){IyeMQMRRWmiL.push(qLmruCVBbFQbWu);}" fullword ascii
    $s18 = "var l = new Array();l[0]=[];l[0][0]='d';l[0][1]='a';l[0][2]='d';l[0][3]='a';l[0][4]='46';l[0][5]='3d';l[0][6]='42';l[0][7]='14';" ascii
    $s19 = "function vdEVObIAPal(mhWZCOPHzENWag) {return isNaN(mhWZCOPHzENWag);}" fullword ascii
    $s20 = "function sUFsxFI(JWUJUKBtsVfGlqQnpCneHOCaTsXqYPSnSuQE) {return !vdEVObIAPal(WpUxuuTrVELmbyj(JWUJUKBtsVfGlqQnpCneHOCaTsXqYPSnSuQE" ascii

  condition:
    uint16(0) == 0x636e and
    8 of them
}