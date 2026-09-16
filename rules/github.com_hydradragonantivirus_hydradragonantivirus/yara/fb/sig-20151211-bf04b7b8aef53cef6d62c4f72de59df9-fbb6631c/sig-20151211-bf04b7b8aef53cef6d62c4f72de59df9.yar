rule sig_20151211_bf04b7b8aef53cef6d62c4f72de59df9 {
  meta:
    description = "datamaliciousorder - file 20151211_bf04b7b8aef53cef6d62c4f72de59df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9453cc4cc7a5dd40e96676dc901d8aab09f23b7d5df0d445b66d24f94d249b9"

  strings:
    $s1  = "var I=new Array(\"2f\",\"29\",\"2a\",\"2d\",\"2a\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s2  = "function PbvKKtipVrKXKJdnF(DKite){MAThTKfSSxR= '';qjHjSfyAQJM=(-685+685)/314; while(true){if(qjHjSfyAQJM >= (-405+923)/259)break" ascii
    $s3  = ";sjQosShCL[qjHjSfyAQJM]=(-872+872)/868; while(true) { if(sjQosShCL[qjHjSfyAQJM] > DKite[qjHjSfyAQJM].length-(486+362)/848) { bre" ascii
    $s4  = "function mrIhRItoMQh(pligUcGg,FUbvMZ){return pligUcGg.split(FUbvMZ)}" fullword ascii
    $s5  = "var I=new Array(\"2f\",\"29\",\"2a\",\"2d\",\"2a\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = " zTwaA;}function daNyMFxfoshFtQp(SiiPqJMIWRKMgOGvi){eval(SiiPqJMIWRKMgOGvi)}" fullword ascii
    $s8  = "function PbvKKtipVrKXKJdnF(DKite){MAThTKfSSxR= '';qjHjSfyAQJM=(-685+685)/314; while(true){if(qjHjSfyAQJM >= (-405+923)/259)break" ascii
    $s9  = "]++;}qjHjSfyAQJM++;} return MAThTKfSSxR}" fullword ascii
    $s10 = "function oZuqU(sbvMvdzJTxN,CFQHmRRfTVYJy,DXIOlbOA){EuAT=parseInt(sbvMvdzJTxN,CFQHmRRfTVYJy);zTwaA=EuAT.toString(DXIOlbOA);return" ascii
    $s11 = "var T=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function oZuqU(sbvMvdzJTxN,CFQHmRRfTVYJy,DXIOlbOA){EuAT=parseInt(sbvMvdzJTxN,CFQHmRRfTVYJy);zTwaA=EuAT.toString(DXIOlbOA);return" ascii
    $s13 = "function tqXzJAF(kCqcWtPXcayMtPnudISjqjpDzRbPACPnKlUx) {return !isNaN(parseFloat(kCqcWtPXcayMtPnudISjqjpDzRbPACPnKlUx)) && isFin" ascii
    $s14 = "function tqXzJAF(kCqcWtPXcayMtPnudISjqjpDzRbPACPnKlUx) {return !isNaN(parseFloat(kCqcWtPXcayMtPnudISjqjpDzRbPACPnKlUx)) && isFin" ascii
    $s15 = "function XHjEcZUejGBTseKwrAipKREDiyrUxGHwIntdltowPqgdcZYgzFoEyJ(EcArcSCTUoPcr,ciZzMYysTSciPo){ return OoqFm[oZuqU(EcArcSCTUoPcr[" ascii
    $s16 = "function XHjEcZUejGBTseKwrAipKREDiyrUxGHwIntdltowPqgdcZYgzFoEyJ(EcArcSCTUoPcr,ciZzMYysTSciPo){ return OoqFm[oZuqU(EcArcSCTUoPcr[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}