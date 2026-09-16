rule sig_20151216_9c35f0b0fde2103f85cf883915be1ce3 {
  meta:
    description = "datamaliciousorder - file 20151216_9c35f0b0fde2103f85cf883915be1ce3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ea648228c6c6d0ee877a0947b0f39d9401ef57e91b80601fa80339bc2c5b7f9"

  strings:
    $s1  = "(Math.cos(531), 2) - 1)));} dIXCRmqHT[IaGDIBDFqcK]++;}IaGDIBDFqcK++;} return xcHvTEjVetd}" fullword ascii
    $s2  = "th.pow(Math.cos(379), 2) - 1)); while(true) { if(dIXCRmqHT[IaGDIBDFqcK] > GgXPs[IaGDIBDFqcK].length-(-575+595)/20) { break; } if" ascii
    $s3  = ") - 1));while(true){if (IaGDIBDFqcK >= (3252+510)/627){break;}dIXCRmqHT[IaGDIBDFqcK]=Math.round((Math.pow(Math.sin(379), 2) + Ma" ascii
    $s4  = "function wTMFurRcvxoMBCKxh(GgXPs){xcHvTEjVetd= '';IaGDIBDFqcK=Math.round((Math.pow(Math.sin(161), 2) + Math.pow(Math.cos(161), 2" ascii
    $s5  = "function wTMFurRcvxoMBCKxh(GgXPs){xcHvTEjVetd= '';IaGDIBDFqcK=Math.round((Math.pow(Math.sin(161), 2) + Math.pow(Math.cos(161), 2" ascii
    $s6  = "function x(NomzmPszTomE,dBInEdLCPdrUVj){NomzmPszTomE.push(dBInEdLCPdrUVj);}" fullword ascii
    $s7  = "function wUDmJqj(yEeCDfFiExTkfiUELkEzrNNydHAjbglyQbPs) {return !sINMKzTSQev(GFyjYAsOVnUEPOk(yEeCDfFiExTkfiUELkEzrNNydHAjbglyQbPs" ascii
    $s8  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s9  = "function KGSkdehUMYDWrtt(jrhFgJLJKUKuAiamF,xtRbdCKmlERqKCLoopImMYpZocVWPtEVBK,DPKeodIzSleeGNEJMzzBdBJRhlNyMpCHMfv){eval(jrhFgJLJ" ascii
    $s10 = "function Vagfa(VEjuHeTBacE,nztKTyjAyhQct,YcrCREQD){nXEo=wEqgsgdyNbwoBswAW(VEjuHeTBacE,nztKTyjAyhQct);ChhoP=nXEo.toString(YcrCREQ" ascii
    $s11 = "function KGSkdehUMYDWrtt(jrhFgJLJKUKuAiamF,xtRbdCKmlERqKCLoopImMYpZocVWPtEVBK,DPKeodIzSleeGNEJMzzBdBJRhlNyMpCHMfv){eval(jrhFgJLJ" ascii
    $s12 = "function GFyjYAsOVnUEPOk(RdAFOvJtZcrStDqCmsM) {return parseFloat(RdAFOvJtZcrStDqCmsM);}" fullword ascii
    $s13 = "function L(jDiNZSKzgRlAgA,KnFCQAyVsRwcO,hrBSfQoGeQZ) {jDiNZSKzgRlAgA[KnFCQAyVsRwcO]=hrBSfQoGeQZ;}" fullword ascii
    $s14 = "D);return ChhoP;}" fullword ascii
    $s15 = "function vgHEFJPjXuqq(YuPFcrpnZtIOy) {return isFinite(YuPFcrpnZtIOy);}" fullword ascii
    $s16 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s17 = "function Vagfa(VEjuHeTBacE,nztKTyjAyhQct,YcrCREQD){nXEo=wEqgsgdyNbwoBswAW(VEjuHeTBacE,nztKTyjAyhQct);ChhoP=nXEo.toString(YcrCREQ" ascii
    $s18 = "function wUDmJqj(yEeCDfFiExTkfiUELkEzrNNydHAjbglyQbPs) {return !sINMKzTSQev(GFyjYAsOVnUEPOk(yEeCDfFiExTkfiUELkEzrNNydHAjbglyQbPs" ascii
    $s19 = "function sINMKzTSQev(DlDxlzMfEvthXv) {return isNaN(DlDxlzMfEvthXv);}" fullword ascii
    $s20 = "function wEqgsgdyNbwoBswAW(dPINbcxHLo,SYLQVfvpdz) {return parseInt(dPINbcxHLo,SYLQVfvpdz);}" fullword ascii

  condition:
    uint16(0) == 0x4f45 and
    8 of them
}