rule sig_20151217_23d7ed6d544d78006b77cd42cb0c9a2b {
  meta:
    description = "datamaliciousorder - file 20151217_23d7ed6d544d78006b77cd42cb0c9a2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a46947ca0db7e158d47414975ca2ca446e65af93a5082fbd71d7617a7e9a5000"

  strings:
    $s1  = "h.pow(Math.cos(59), 2) - 1)); while(true) { if(xkpWmMiVj[IcvjNzPdXsE] > MtKfH[IcvjNzPdXsE].length-(-583+661)/78) { break; } if (" ascii
    $s2  = "function vPiKpNySeFHUXbtii(MtKfH){etqQMNUGejE= '';IcvjNzPdXsE=Math.round((Math.pow(Math.sin(468), 2) + Math.pow(Math.cos(468), 2" ascii
    $s3  = ") - 1));while(true){if (IcvjNzPdXsE >= (4862+670)/922){break;}xkpWmMiVj[IcvjNzPdXsE]=Math.round((Math.pow(Math.sin(59), 2) + Mat" ascii
    $s4  = "(Math.cos(821), 2) - 1)));} xkpWmMiVj[IcvjNzPdXsE]++;}IcvjNzPdXsE++;} return etqQMNUGejE}" fullword ascii
    $s5  = "function vPiKpNySeFHUXbtii(MtKfH){etqQMNUGejE= '';IcvjNzPdXsE=Math.round((Math.pow(Math.sin(468), 2) + Math.pow(Math.cos(468), 2" ascii
    $s6  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s7  = "function keWbweryjbDoHyKMc(qhxkjPDYVK,ppYlHSjKHU) {return parseInt(qhxkjPDYVK,ppYlHSjKHU);}" fullword ascii
    $s8  = "function N(GesvOtUdqenThM,SzGrVjKVIAkmd,nGJyCGMshYK) {GesvOtUdqenThM[SzGrVjKVIAkmd]=nGJyCGMshYK;}" fullword ascii
    $s9  = "function tGcyQyJDVYpijOs(mlTnAiVqTWQzqXNMj,fjaThTfYzLKLEUUukfFcYhPPxqbYzejJFg,kfLQloMliYIxEkreXnmjzMrFTLpGFiRbvgc){eval(mlTnAiVq" ascii
    $s10 = "function UePCywBCYKNCQDT(kgmYyFgQiFMJsuHsKbw) {return parseFloat(kgmYyFgQiFMJsuHsKbw);}" fullword ascii
    $s11 = "e);return xVRiy;}" fullword ascii
    $s12 = "function zEvZRjyCOAvKVoNmtuPipOtXohBDQvuUdtolgmkWsRBfcoEWssAkJX(WDpEmzrWFzYVe,PCMHgClzZLePRE){ return rjFlTkc[QbVdBAtP[SFoqM(WDp" ascii
    $s13 = "function tGcyQyJDVYpijOs(mlTnAiVqTWQzqXNMj,fjaThTfYzLKLEUUukfFcYhPPxqbYzejJFg,kfLQloMliYIxEkreXnmjzMrFTLpGFiRbvgc){eval(mlTnAiVq" ascii
    $s14 = "function TxgrRTzLvNA(WiwhIBmXNzdIYY) {return isNaN(WiwhIBmXNzdIYY);}" fullword ascii
    $s15 = "function zEvZRjyCOAvKVoNmtuPipOtXohBDQvuUdtolgmkWsRBfcoEWssAkJX(WDpEmzrWFzYVe,PCMHgClzZLePRE){ return rjFlTkc[QbVdBAtP[SFoqM(WDp" ascii
    $s16 = "function p(CrsricMKEeJc,ueHMMyyJQmPPhl){CrsricMKEeJc.push(ueHMMyyJQmPPhl);}" fullword ascii
    $s17 = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s18 = "function dMuGZfcFYFWz(cKOMQwZoEqKvh) {return isFinite(cKOMQwZoEqKvh);}" fullword ascii
    $s19 = "function SFoqM(oDgawjfVPrR,eajODIinZcPIM,yomvtIRe){KwCP=keWbweryjbDoHyKMc(oDgawjfVPrR,eajODIinZcPIM);xVRiy=KwCP.toString(yomvtIR" ascii
    $s20 = "function SFoqM(oDgawjfVPrR,eajODIinZcPIM,yomvtIRe){KwCP=keWbweryjbDoHyKMc(oDgawjfVPrR,eajODIinZcPIM);xVRiy=KwCP.toString(yomvtIR" ascii

  condition:
    uint16(0) == 0x6251 and
    8 of them
}