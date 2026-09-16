rule sig_20151215_ca8928fed404f02968394f92b8d28551 {
  meta:
    description = "datamaliciousorder - file 20151215_ca8928fed404f02968394f92b8d28551.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42dd6a6152e1eca76ddab571f901eeb29f06a55f7cea7b6bc1d0527da4abd7b4"

  strings:
    $s1  = "ath.pow(Math.cos(476), 2) - 1)); while(true) { if(SRWHgbheB[gclLAGlgrlT] > hbYNZ[gclLAGlgrlT].length-(528+384)/912) { break; } i" ascii
    $s2  = ".pow(Math.cos(916), 2) - 1)));} SRWHgbheB[gclLAGlgrlT]++;}} return KFwZsHHxGjs}" fullword ascii
    $s3  = "function NujkRRisiFSXoacYH(hbYNZ){KFwZsHHxGjs= m[1777];for(gclLAGlgrlT=Math.round((Math.pow(Math.sin(863), 2) + Math.pow(Math.co" ascii
    $s4  = "function NujkRRisiFSXoacYH(hbYNZ){KFwZsHHxGjs= m[1777];for(gclLAGlgrlT=Math.round((Math.pow(Math.sin(863), 2) + Math.pow(Math.co" ascii
    $s5  = "terNdGePmFcQWqcpleGfVdjgBwaPjPHifZIS([hbYNZ[gclLAGlgrlT][SRWHgbheB[gclLAGlgrlT]]], Math.round((Math.pow(Math.sin(916), 2) + Math" ascii
    $s6  = "ErSG)) {return (String.fromCharCode(XomILhZHeRYtErSG) + String.fromCharCode((34697+971)/964));}}" fullword ascii
    $s7  = "function zbcDl(nxhGrtLhzZC,xtMhMtmmUdPwi,psmCgLOU){TwQr=parseInt(nxhGrtLhzZC,xtMhMtmmUdPwi);HCGbF=TwQr.toString(psmCgLOU);return" ascii
    $s8  = "function zbcDl(nxhGrtLhzZC,xtMhMtmmUdPwi,psmCgLOU){TwQr=parseInt(nxhGrtLhzZC,xtMhMtmmUdPwi);HCGbF=TwQr.toString(psmCgLOU);return" ascii
    $s9  = "function ruMdWSFbWpY(XDlvZiwr,VRGsMG){return XDlvZiwr.split(VRGsMG)}" fullword ascii
    $s10 = " HCGbF;}function AcsQUDgIZZZibTm(fdEsWdElYttaYpfWK,crvjabPuZNWZhXBeQmfcJBQLLsQlSsIfTT,BQowlRNUGWUlnXbyrppiTLAFzSdpyvRWBWa){eval(" ascii
    $s11 = "function AcsQUDgIZZZibTm(fdEsWdElYttaYpfWK){eval(fdEsWdElYttaYpfWK)}" fullword ascii
    $s12 = "function j(KxIPjZwaUxYu,iLpzEnfdrDIJem){KxIPjZwaUxYu.push(iLpzEnfdrDIJem);}function v8(XomILhZHeRYtErSG){if(WpwOcRL(XomILhZHeRYt" ascii
    $s13 = "function VeRmodBSMXCtbeSwOtterNdGePmFcQWqcpleGfVdjgBwaPjPHifZIS(SUypBgBKrNqSW,xjZzUlPYynuVhB){ return gNmMkeu[itLrUTTA[zbcDl(SUy" ascii
    $s14 = "function VeRmodBSMXCtbeSwOtterNdGePmFcQWqcpleGfVdjgBwaPjPHifZIS(SUypBgBKrNqSW,xjZzUlPYynuVhB){ return gNmMkeu[itLrUTTA[zbcDl(SUy" ascii
    $s15 = "function WpwOcRL(hHDspQjyMHTGbqGIeDXcjTYqIgCuQjIXIQNs) {return !isNaN(parseFloat(hHDspQjyMHTGbqGIeDXcjTYqIgCuQjIXIQNs)) && isFin" ascii
    $s16 = "function WpwOcRL(hHDspQjyMHTGbqGIeDXcjTYqIgCuQjIXIQNs) {return !isNaN(parseFloat(hHDspQjyMHTGbqGIeDXcjTYqIgCuQjIXIQNs)) && isFin" ascii
    $s17 = "function j(KxIPjZwaUxYu,iLpzEnfdrDIJem){KxIPjZwaUxYu.push(iLpzEnfdrDIJem);}function v8(XomILhZHeRYtErSG){if(WpwOcRL(XomILhZHeRYt" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}