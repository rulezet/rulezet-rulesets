rule sig_20151210_eb63ae3287446402ae11c66d9f5e47e3 {
  meta:
    description = "datamaliciousorder - file 20151210_eb63ae3287446402ae11c66d9f5e47e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01c305e7b3028dfacfe81114a05fab20bd9071426f8bb42cb9393fe7c8f2c313"

  strings:
    $s1  = "function mQvSBOp(GwciVvuYHrbNJwAOWigqSdyUaalAyuFoqOUE) {return !isNaN(parseFloat(GwciVvuYHrbNJwAOWigqSdyUaalAyuFoqOUE)) && isFin" ascii
    $s2  = "function mQvSBOp(GwciVvuYHrbNJwAOWigqSdyUaalAyuFoqOUE) {return !isNaN(parseFloat(GwciVvuYHrbNJwAOWigqSdyUaalAyuFoqOUE)) && isFin" ascii
    $s3  = "function chQnxIytBCgOdbNmsHsLwZPdaQRVSyVnhnkvdDOElhzReusPbIYSoB(xMzCpTwFTuKEQ,dGfdTfoqzxfzAt){ return PLEzhvPcVNODQ[LtZyV(xMzCpT" ascii
    $s4  = "function DoVOiFtIUuINmgemI(epTeD){IYCWcyIcCOi= '';for(EqvpTSwvEgf=(-892+892)/13; EqvpTSwvEgf < (603+781)/692; EqvpTSwvEgf++) {uY" ascii
    $s5  = "function LtZyV(HLMZvzLUgXF,RdzozcIxXZgti,njrObntq){SFRM=parseInt(HLMZvzLUgXF,RdzozcIxXZgti);smHto=SFRM.toString(njrObntq);return" ascii
    $s6  = "QHrBVFH=(-644+644)/404;while(true){if(QHrBVFH>=(76841+215)/602){break;}PLEzhvPcVNODQ[QHrBVFH]=String.fromCharCode(QHrBVFH);QHrBV" ascii
    $s7  = "function chQnxIytBCgOdbNmsHsLwZPdaQRVSyVnhnkvdDOElhzReusPbIYSoB(xMzCpTwFTuKEQ,dGfdTfoqzxfzAt){ return PLEzhvPcVNODQ[LtZyV(xMzCpT" ascii
    $s8  = "function LtZyV(HLMZvzLUgXF,RdzozcIxXZgti,njrObntq){SFRM=parseInt(HLMZvzLUgXF,RdzozcIxXZgti);smHto=SFRM.toString(njrObntq);return" ascii
    $s9  = " smHto;}function BTVvwnLkTqVXdzX(MPKuTcyPYptPBWApI){eval(MPKuTcyPYptPBWApI)}" fullword ascii
    $s10 = "DCUtEqs[EqvpTSwvEgf]=(-901+901)/332; while(true) { if(uYDCUtEqs[EqvpTSwvEgf] > epTeD[EqvpTSwvEgf].length-(-695+829)/134) { break" ascii
    $s11 = "QHrBVFH=(-644+644)/404;while(true){if(QHrBVFH>=(76841+215)/602){break;}PLEzhvPcVNODQ[QHrBVFH]=String.fromCharCode(QHrBVFH);QHrBV" ascii
    $s12 = "} return IYCWcyIcCOi}" fullword ascii
    $s13 = "function DoVOiFtIUuINmgemI(epTeD){IYCWcyIcCOi= '';for(EqvpTSwvEgf=(-892+892)/13; EqvpTSwvEgf < (603+781)/692; EqvpTSwvEgf++) {uY" ascii
    $s14 = "function KAVEOqzjqOv(FLaAkbmj,jylMPW){return FLaAkbmj.split(jylMPW)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}