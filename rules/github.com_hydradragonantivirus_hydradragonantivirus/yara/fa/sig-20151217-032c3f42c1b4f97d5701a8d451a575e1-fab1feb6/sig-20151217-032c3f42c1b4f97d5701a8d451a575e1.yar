rule sig_20151217_032c3f42c1b4f97d5701a8d451a575e1 {
  meta:
    description = "datamaliciousorder - file 20151217_032c3f42c1b4f97d5701a8d451a575e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3851badd628a444f10d66730e83eac3a9aefe8f3d6e38fd78fbd60af1d25e99"

  strings:
    $s1  = "th.pow(Math.cos(557), 2) - 1)); while(true) { if(zQdeJNahj[BMHwqbTWQVM] > mhjOF[BMHwqbTWQVM].length-(-363+648)/285) { break; } i" ascii
    $s2  = "w(Math.cos(438), 2) - 1)));} zQdeJNahj[BMHwqbTWQVM]++;}BMHwqbTWQVM++;} return hABJMkiSfzl}" fullword ascii
    $s3  = "function JgqQaIVqUYXtQHTMu(mhjOF){hABJMkiSfzl= '';BMHwqbTWQVM=Math.round((Math.pow(Math.sin(350), 2) + Math.pow(Math.cos(350), 2" ascii
    $s4  = ") - 1));while(true){if (BMHwqbTWQVM >= (5206+668)/979){break;}zQdeJNahj[BMHwqbTWQVM]=Math.round((Math.pow(Math.sin(557), 2) + Ma" ascii
    $s5  = "function JgqQaIVqUYXtQHTMu(mhjOF){hABJMkiSfzl= '';BMHwqbTWQVM=Math.round((Math.pow(Math.sin(350), 2) + Math.pow(Math.cos(350), 2" ascii
    $s6  = "function VaBtYCchcOGJcSaiRxePtIinhxEIcPmtLkZfSoYsXQxFOUfmVUINrJ(WOPILukkozVap,ZcFkJgCGBeyeyg){ return SmMzCqv[nCkJRtmO[xBLxr(WOP" ascii
    $s7  = "function VaBtYCchcOGJcSaiRxePtIinhxEIcPmtLkZfSoYsXQxFOUfmVUINrJ(WOPILukkozVap,ZcFkJgCGBeyeyg){ return SmMzCqv[nCkJRtmO[xBLxr(WOP" ascii
    $s8  = "function kNpnMIJVWjZckIaQL(gLTaEjfkGH,uVOcHWswCl) {return parseInt(gLTaEjfkGH,uVOcHWswCl);}" fullword ascii
    $s9  = "function F(hxyrfedvvnrj,xknioolcSpgDQu){hxyrfedvvnrj.push(xknioolcSpgDQu);}" fullword ascii
    $s10 = "function I(oTZhrNaWGhXeiy,zkQwrXOBKHExB,QjsNBjwsqfB) {oTZhrNaWGhXeiy[zkQwrXOBKHExB]=QjsNBjwsqfB;}" fullword ascii
    $s11 = "function eXuUXAlFIWbx(cHTncMiBuJzAN) {return isFinite(cHTncMiBuJzAN);}" fullword ascii
    $s12 = "function DOghSDqaJcPtARY(IPFosLnvKrdtzuzol,wQwjngdCUubYfipTaLwKCQyZZNiPHsydLe,rovgBeLWogoGIqLXMbZGxRQZgyekVcmJdlT){eval(IPFosLnv" ascii
    $s13 = "function DOghSDqaJcPtARY(IPFosLnvKrdtzuzol,wQwjngdCUubYfipTaLwKCQyZZNiPHsydLe,rovgBeLWogoGIqLXMbZGxRQZgyekVcmJdlT){eval(IPFosLnv" ascii
    $s14 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s15 = "function xBLxr(lDVSaZtHwfj,DEpJAEpTMitGO,xpdSIcgs){JoAT=kNpnMIJVWjZckIaQL(lDVSaZtHwfj,DEpJAEpTMitGO);fuLLV=JoAT.toString(xpdSIcg" ascii
    $s16 = "s);return fuLLV;}" fullword ascii
    $s17 = "function WIoIpnmeGKp(TQhfLATgairLjs) {return isNaN(TQhfLATgairLjs);}" fullword ascii
    $s18 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s19 = "function xBLxr(lDVSaZtHwfj,DEpJAEpTMitGO,xpdSIcgs){JoAT=kNpnMIJVWjZckIaQL(lDVSaZtHwfj,DEpJAEpTMitGO);fuLLV=JoAT.toString(xpdSIcg" ascii
    $s20 = "function KnSMNSd(dcRhAZbfLxleCAeGEsIPSrYmlmmMqZLTEvkC) {return !WIoIpnmeGKp(ACnccdRjiVOcABG(dcRhAZbfLxleCAeGEsIPSrYmlmmMqZLTEvkC" ascii

  condition:
    uint16(0) == 0x436e and
    8 of them
}