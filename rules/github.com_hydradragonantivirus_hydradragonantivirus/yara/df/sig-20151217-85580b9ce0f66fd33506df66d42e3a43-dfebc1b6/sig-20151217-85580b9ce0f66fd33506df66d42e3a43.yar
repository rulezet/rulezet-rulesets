rule sig_20151217_85580b9ce0f66fd33506df66d42e3a43 {
  meta:
    description = "datamaliciousorder - file 20151217_85580b9ce0f66fd33506df66d42e3a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c46ae7e0ef3d11663504cb37e37a90b776539628ae18a1694c418f26c4696818"

  strings:
    $s1  = "w(Math.cos(190), 2) - 1)));} dSepgdmAr[FjUJWGOvZZT]++;}FjUJWGOvZZT++;} return CkcVXHKqFVr}" fullword ascii
    $s2  = ") - 1));while(true){if (FjUJWGOvZZT >= (547+719)/211){break;}dSepgdmAr[FjUJWGOvZZT]=Math.round((Math.pow(Math.sin(729), 2) + Mat" ascii
    $s3  = "function WGGbdREwonleMMxjx(lSSUa){CkcVXHKqFVr= '';FjUJWGOvZZT=Math.round((Math.pow(Math.sin(122), 2) + Math.pow(Math.cos(122), 2" ascii
    $s4  = "h.pow(Math.cos(729), 2) - 1)); while(true) { if(dSepgdmAr[FjUJWGOvZZT] > lSSUa[FjUJWGOvZZT].length-(297+163)/460) { break; } if " ascii
    $s5  = "function WGGbdREwonleMMxjx(lSSUa){CkcVXHKqFVr= '';FjUJWGOvZZT=Math.round((Math.pow(Math.sin(122), 2) + Math.pow(Math.cos(122), 2" ascii
    $s6  = "function drnmIvV(TXKkCJrVpqBHGfTQUzlXvvFcmWEnAqsGvbOh) {return !zqvenhWKedx(KKybjItLyKKlmHd(TXKkCJrVpqBHGfTQUzlXvvFcmWEnAqsGvbOh" ascii
    $s7  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s8  = "function niXUdsZnLYmbqxgmdgaeaYCxUuoMnuGErAWIaYSgipitkADWlQsvvY(gmsyHYkWrBQjC,tkjeDOUvpGYMdn){ return VqVcquR[TwlcLYJv[pVUqM(gms" ascii
    $s9  = "l);return qMQlR;}" fullword ascii
    $s10 = "function KKybjItLyKKlmHd(wDNdeGzrOFtjONVGJWO) {return parseFloat(wDNdeGzrOFtjONVGJWO);}" fullword ascii
    $s11 = "function drnmIvV(TXKkCJrVpqBHGfTQUzlXvvFcmWEnAqsGvbOh) {return !zqvenhWKedx(KKybjItLyKKlmHd(TXKkCJrVpqBHGfTQUzlXvvFcmWEnAqsGvbOh" ascii
    $s12 = "function b(BqYgtyxaaJsU,itOsdbWNFzuYQN){BqYgtyxaaJsU.push(itOsdbWNFzuYQN);}" fullword ascii
    $s13 = "function PkBDDAoEWaRzAjj(IekkGeqYdMRelKcRs,UdZyOGwCTrPSGLYPozBNHQpBwTNAWxnYjU,JxnrYhpJNKJyUubrerFMnIKpjArSMKxceuj){eval(IekkGeqY" ascii
    $s14 = "function pVUqM(DFuyCtRRold,RcuBvvPSUiZaq,KAuwdGyl){lcEN=zvMDrQyKiOVrklcKB(DFuyCtRRold,RcuBvvPSUiZaq);qMQlR=lcEN.toString(KAuwdGy" ascii
    $s15 = "function zqvenhWKedx(HVmfNhIMhNOacI) {return isNaN(HVmfNhIMhNOacI);}" fullword ascii
    $s16 = "function pVUqM(DFuyCtRRold,RcuBvvPSUiZaq,KAuwdGyl){lcEN=zvMDrQyKiOVrklcKB(DFuyCtRRold,RcuBvvPSUiZaq);qMQlR=lcEN.toString(KAuwdGy" ascii
    $s17 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s18 = "function rVRVzONHbzYG(XIvPBgyyMgkgx) {return isFinite(XIvPBgyyMgkgx);}" fullword ascii
    $s19 = "function PkBDDAoEWaRzAjj(IekkGeqYdMRelKcRs,UdZyOGwCTrPSGLYPozBNHQpBwTNAWxnYjU,JxnrYhpJNKJyUubrerFMnIKpjArSMKxceuj){eval(IekkGeqY" ascii
    $s20 = "function zvMDrQyKiOVrklcKB(wciDJgkAqX,jgasaezxse) {return parseInt(wciDJgkAqX,jgasaezxse);}" fullword ascii

  condition:
    uint16(0) == 0x7754 and
    8 of them
}