rule sig_20151217_91938580549f5242360aef1054552553 {
  meta:
    description = "datamaliciousorder - file 20151217_91938580549f5242360aef1054552553.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1075e812fb20a6881f03ea7cfa86cda340a1925987021541d7517eddfecbf276"

  strings:
    $s1  = ") - 1));while(true){if (PrErEfhZhff >= (2567+337)/484){break;}MJhupirmP[PrErEfhZhff]=Math.round((Math.pow(Math.sin(464), 2) + Ma" ascii
    $s2  = ".pow(Math.cos(954), 2) - 1)));} MJhupirmP[PrErEfhZhff]++;}PrErEfhZhff++;} return uVjsmMwNPWP}" fullword ascii
    $s3  = "th.pow(Math.cos(464), 2) - 1)); while(true) { if(MJhupirmP[PrErEfhZhff] > goiDJ[PrErEfhZhff].length-(-520+802)/282) { break; } i" ascii
    $s4  = "function bjSCvHNhRRYcuWdHm(goiDJ){uVjsmMwNPWP= '';PrErEfhZhff=Math.round((Math.pow(Math.sin(457), 2) + Math.pow(Math.cos(457), 2" ascii
    $s5  = "function bjSCvHNhRRYcuWdHm(goiDJ){uVjsmMwNPWP= '';PrErEfhZhff=Math.round((Math.pow(Math.sin(457), 2) + Math.pow(Math.cos(457), 2" ascii
    $s6  = "PRWlmBACrjtyptiKrWbuzWSePjufXaTDxUeA([goiDJ[PrErEfhZhff][MJhupirmP[PrErEfhZhff]]], Math.round((Math.pow(Math.sin(954), 2) + Math" ascii
    $s7  = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s8  = "function xgHLGdLAUHjU(IoVcNCqOXQKBf) {return isFinite(IoVcNCqOXQKBf);}" fullword ascii
    $s9  = "P);return Ahmie;}" fullword ascii
    $s10 = "function jhloyGHcFLLgfmS(kxmXzZfvhiSaqCfSnKC) {return parseFloat(kxmXzZfvhiSaqCfSnKC);}" fullword ascii
    $s11 = "function pRmjiGCKhKrsdkJQrCPRWlmBACrjtyptiKrWbuzWSePjufXaTDxUeA(qbEsAapBdmGaR,BiQzylNKDtgYwz){ return gpDpDOC[cXddgChW[OGJsQ(qbE" ascii
    $s12 = "function OGJsQ(wtMFEWhRqUl,FAZHGWopeRkmp,WgFbeFcP){fxGg=VvIJMsQWbSQdSEELa(wtMFEWhRqUl,FAZHGWopeRkmp);Ahmie=fxGg.toString(WgFbeFc" ascii
    $s13 = "function rMauqpjSfYW(FlbfideEpDiWLz) {return isNaN(FlbfideEpDiWLz);}" fullword ascii
    $s14 = "function n(RPLlqtQFgguD,sIYzKzmmolKjZL){RPLlqtQFgguD.push(sIYzKzmmolKjZL);}" fullword ascii
    $s15 = "function V(ptOyZGqtHMWRyQ,tdsPnQJlocGio,mRrTRTOFVDO) {ptOyZGqtHMWRyQ[tdsPnQJlocGio]=mRrTRTOFVDO;}" fullword ascii
    $s16 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s17 = "function pRmjiGCKhKrsdkJQrCPRWlmBACrjtyptiKrWbuzWSePjufXaTDxUeA(qbEsAapBdmGaR,BiQzylNKDtgYwz){ return gpDpDOC[cXddgChW[OGJsQ(qbE" ascii
    $s18 = "function OGJsQ(wtMFEWhRqUl,FAZHGWopeRkmp,WgFbeFcP){fxGg=VvIJMsQWbSQdSEELa(wtMFEWhRqUl,FAZHGWopeRkmp);Ahmie=fxGg.toString(WgFbeFc" ascii
    $s19 = "function YISkcYFlnErIqWu(DlrPTuxYbVPCrvPKz,gUkyzcgnVWJaZUQhBXZXCZTtIhUhvpLzkU,CDKuxzquYRxtxGrTICxTTpxnneSBqqTJdMi){eval(DlrPTuxY" ascii
    $s20 = ",'?','D',' ',';','$','q','W','?','5','Z','B','x','X','B','J','5','Y',']',']','{','[','%','1','Z','p','[','%','>','d','r',String." ascii

  condition:
    uint16(0) == 0x5863 and
    8 of them
}