rule sig_20151211_9f709810d169efd7f1f40e2dd66292c3 {
  meta:
    description = "datamaliciousorder - file 20151211_9f709810d169efd7f1f40e2dd66292c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b9daf8a631a883ee8b523a642dd9e991e774790ef3b26b373b21d2fc17aaad5"

  strings:
    $s1  = "function xRVDLeYeGbmxMyquaxFFLZPIzoCbgzxSYrCvToLsSNMSJtmXhwmTpO(SRAWrRKHIlEVO,DRzZdaheQDeMcm){ return HsSBz[IMcrn(SRAWrRKHIlEVO[" ascii
    $s2  = "function xRVDLeYeGbmxMyquaxFFLZPIzoCbgzxSYrCvToLsSNMSJtmXhwmTpO(SRAWrRKHIlEVO,DRzZdaheQDeMcm){ return HsSBz[IMcrn(SRAWrRKHIlEVO[" ascii
    $s3  = "function CGPbskRgIlxrhOIao(TBVyc){LYQIJsKVBKa= '';nHHOIxIpHbW=(-892+892)/61; while(true){if(nHHOIxIpHbW >= (526+762)/644)break;o" ascii
    $s4  = "function CwSjeUy(wtsVeUuWkBxFnxRUjOJFHMWDJdHDOGEehGjP) {return !isNaN(parseFloat(wtsVeUuWkBxFnxRUjOJFHMWDJdHDOGEehGjP)) && isFin" ascii
    $s5  = "function CwSjeUy(wtsVeUuWkBxFnxRUjOJFHMWDJdHDOGEehGjP) {return !isNaN(parseFloat(wtsVeUuWkBxFnxRUjOJFHMWDJdHDOGEehGjP)) && isFin" ascii
    $s6  = "function CGPbskRgIlxrhOIao(TBVyc){LYQIJsKVBKa= '';nHHOIxIpHbW=(-892+892)/61; while(true){if(nHHOIxIpHbW >= (526+762)/644)break;o" ascii
    $s7  = "var y=new Array(\"2e\",\"28\",\"2e\",\"2c\",\"2f\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "qJZNBlgu[nHHOIxIpHbW]=(-413+413)/969; while(true) { if(oqJZNBlgu[nHHOIxIpHbW] > TBVyc[nHHOIxIpHbW].length-(-709+729)/20) { break" ascii
    $s9  = "function aBGJgCOXPli(AdCUPfqk,lcUJHt){return AdCUPfqk.split(lcUJHt)}" fullword ascii
    $s10 = "function IMcrn(rFBKdbhfPjb,WIMNRwIFNwgyF,hFzPYTlc){OXUZ=parseInt(rFBKdbhfPjb,WIMNRwIFNwgyF);KBlEi=OXUZ.toString(hFzPYTlc);return" ascii
    $s11 = "var z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s12 = "function IMcrn(rFBKdbhfPjb,WIMNRwIFNwgyF,hFzPYTlc){OXUZ=parseInt(rFBKdbhfPjb,WIMNRwIFNwgyF);KBlEi=OXUZ.toString(hFzPYTlc);return" ascii
    $s13 = "var y=new Array(\"2e\",\"28\",\"2e\",\"2c\",\"2f\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = " KBlEi;}function CreRjFzirZXCimx(BaIFJegTqkRhbYWXj){eval(BaIFJegTqkRhbYWXj)}" fullword ascii
    $s15 = "OIxIpHbW++;} return LYQIJsKVBKa}" fullword ascii
    $s16 = "var z=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3f\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}