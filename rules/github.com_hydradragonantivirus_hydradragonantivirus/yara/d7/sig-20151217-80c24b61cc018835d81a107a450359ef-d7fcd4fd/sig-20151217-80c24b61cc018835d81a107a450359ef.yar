rule sig_20151217_80c24b61cc018835d81a107a450359ef {
  meta:
    description = "datamaliciousorder - file 20151217_80c24b61cc018835d81a107a450359ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ff8baac6aabc48411354e455d78911531092a0f032c4f301838201d117dd9bd"

  strings:
    $s1  = ") - 1));while(true){if (lSLasYFgtmR >= (303+765)/178){break;}QhsXVYabw[lSLasYFgtmR]=Math.round((Math.pow(Math.sin(185), 2) + Mat" ascii
    $s2  = "w(Math.cos(756), 2) - 1)));} QhsXVYabw[lSLasYFgtmR]++;}lSLasYFgtmR++;} return MMnZoleGEXX}" fullword ascii
    $s3  = "function tbpjDbnqfxIcZtdgt(iQTOI){MMnZoleGEXX= '';lSLasYFgtmR=Math.round((Math.pow(Math.sin(904), 2) + Math.pow(Math.cos(904), 2" ascii
    $s4  = "h.pow(Math.cos(185), 2) - 1)); while(true) { if(QhsXVYabw[lSLasYFgtmR] > iQTOI[lSLasYFgtmR].length-(-414+989)/575) { break; } if" ascii
    $s5  = "function tbpjDbnqfxIcZtdgt(iQTOI){MMnZoleGEXX= '';lSLasYFgtmR=Math.round((Math.pow(Math.sin(904), 2) + Math.pow(Math.cos(904), 2" ascii
    $s6  = "function THKyJ(ncObSPywcdZ,keXmFLCxEnMIA,TYKrTvtA){nZjK=nyjfSJFMXqInrmRsD(ncObSPywcdZ,keXmFLCxEnMIA);gSzuN=nZjK.toString(TYKrTvt" ascii
    $s7  = "function THKyJ(ncObSPywcdZ,keXmFLCxEnMIA,TYKrTvtA){nZjK=nyjfSJFMXqInrmRsD(ncObSPywcdZ,keXmFLCxEnMIA);gSzuN=nZjK.toString(TYKrTvt" ascii
    $s8  = "function KBGCLIR(ZYqEjrsHPMcfYrnvVxXBJInSKxrktOfRhzhm) {return !rmoSvFgnNkW(atJpIjaPMkyZuJf(ZYqEjrsHPMcfYrnvVxXBJInSKxrktOfRhzhm" ascii
    $s9  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s10 = "function i(omzgPYgTGysgTR,FBpvDWDvYilrf,SIpDntwKeIk) {omzgPYgTGysgTR[FBpvDWDvYilrf]=SIpDntwKeIk;}" fullword ascii
    $s11 = "function QlOhPyrajIdobre(TpHxwiHnEJhjFxelO,drIZkmNZYiSLXhVPqNbQDxhpQsLTagyxiP,UFdDEfpvtPkmgkNCuUJpTfzYNNwNRPuNCYn){eval(TpHxwiHn" ascii
    $s12 = "function rmoSvFgnNkW(SfxsraDJGDTbnS) {return isNaN(SfxsraDJGDTbnS);}" fullword ascii
    $s13 = "function uBjFFhAiUZmN(BsTQXKVJjJuLl) {return isFinite(BsTQXKVJjJuLl);}" fullword ascii
    $s14 = "function xAfDcFZfqSaEtPTJGkQmcMZwsqpJSlrmaDtLJJESnUUKmrSgvZTHcx(hVhomJTGePgaM,vVFvFtSEKgRYWO){ return eLIUCiy[HiBPorzE[THKyJ(hVh" ascii
    $s15 = "function m(KeUArbwYMesV,sbocGqEBOSFLCq){KeUArbwYMesV.push(sbocGqEBOSFLCq);}" fullword ascii
    $s16 = "function xAfDcFZfqSaEtPTJGkQmcMZwsqpJSlrmaDtLJJESnUUKmrSgvZTHcx(hVhomJTGePgaM,vVFvFtSEKgRYWO){ return eLIUCiy[HiBPorzE[THKyJ(hVh" ascii
    $s17 = "function nyjfSJFMXqInrmRsD(diaKLhMStt,rPMrJEVGfb) {return parseInt(diaKLhMStt,rPMrJEVGfb);}" fullword ascii
    $s18 = "function atJpIjaPMkyZuJf(HQjCHUFcJUnhZCLPMyl) {return parseFloat(HQjCHUFcJUnhZCLPMyl);}" fullword ascii
    $s19 = "function QlOhPyrajIdobre(TpHxwiHnEJhjFxelO,drIZkmNZYiSLXhVPqNbQDxhpQsLTagyxiP,UFdDEfpvtPkmgkNCuUJpTfzYNNwNRPuNCYn){eval(TpHxwiHn" ascii
    $s20 = "function KBGCLIR(ZYqEjrsHPMcfYrnvVxXBJInSKxrktOfRhzhm) {return !rmoSvFgnNkW(atJpIjaPMkyZuJf(ZYqEjrsHPMcfYrnvVxXBJInSKxrktOfRhzhm" ascii

  condition:
    uint16(0) == 0x6948 and
    8 of them
}