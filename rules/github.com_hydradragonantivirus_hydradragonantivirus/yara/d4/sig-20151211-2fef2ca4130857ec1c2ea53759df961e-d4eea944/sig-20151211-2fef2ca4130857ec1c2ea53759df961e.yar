rule sig_20151211_2fef2ca4130857ec1c2ea53759df961e {
  meta:
    description = "datamaliciousorder - file 20151211_2fef2ca4130857ec1c2ea53759df961e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e344e5a176eecac722be4bbf35c1d2d9678a47f14a871715216e8eec462011bb"

  strings:
    $s1  = "gkAXHPk[WMmRWlOgFxA]=(-371+371)/63; while(true) { if(LTgkAXHPk[WMmRWlOgFxA] > uMFbw[WMmRWlOgFxA].length-(92+642)/734) { break; }" ascii
    $s2  = "mRWlOgFxA++;} return wpzQEGqtnEB}" fullword ascii
    $s3  = "function HKFklCsuLYlxhfKVn(uMFbw){wpzQEGqtnEB= '';WMmRWlOgFxA=(-29+29)/137; while(true){if(WMmRWlOgFxA >= (491+801)/646)break;LT" ascii
    $s4  = "function HKFklCsuLYlxhfKVn(uMFbw){wpzQEGqtnEB= '';WMmRWlOgFxA=(-29+29)/137; while(true){if(WMmRWlOgFxA >= (491+801)/646)break;LT" ascii
    $s5  = "function oZFVAsf(rLfpopSOOcIjyGFvQiurdRMJjrUbtXICwjws) {return !isNaN(parseFloat(rLfpopSOOcIjyGFvQiurdRMJjrUbtXICwjws)) && isFin" ascii
    $s6  = "function oZFVAsf(rLfpopSOOcIjyGFvQiurdRMJjrUbtXICwjws) {return !isNaN(parseFloat(rLfpopSOOcIjyGFvQiurdRMJjrUbtXICwjws)) && isFin" ascii
    $s7  = " KxNWZ;}function kcwbaqKCsjUMauK(MhOXwrhxsWjRyHGWj){eval(MhOXwrhxsWjRyHGWj)}" fullword ascii
    $s8  = "function YMZqDgzsuOPwhlpigXVouuCGkACbTIwJQKnSzMiAcjrFWLpQpuHOve(EtPYBYPQMmKVk,RgKYbCcNChhxHq){ return BnITs[mkvls(EtPYBYPQMmKVk[" ascii
    $s9  = "function mkvls(XKPrOIuqaDe,BeLVXVuuSPjIP,sANrcirl){kPGq=parseInt(XKPrOIuqaDe,BeLVXVuuSPjIP);KxNWZ=kPGq.toString(sANrcirl);return" ascii
    $s10 = "var k=new Array(\"29\",\"2f\",\"2a\",\"2c\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s11 = "function QGIppAggDhV(xYCvAZKa,lRiuIh){return xYCvAZKa.split(lRiuIh)}" fullword ascii
    $s12 = "var k=new Array(\"29\",\"2f\",\"2a\",\"2c\",\"2c\",\"27\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "function mkvls(XKPrOIuqaDe,BeLVXVuuSPjIP,sANrcirl){kPGq=parseInt(XKPrOIuqaDe,BeLVXVuuSPjIP);KxNWZ=kPGq.toString(sANrcirl);return" ascii
    $s14 = "var s=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "var s=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "function YMZqDgzsuOPwhlpigXVouuCGkACbTIwJQKnSzMiAcjrFWLpQpuHOve(EtPYBYPQMmKVk,RgKYbCcNChhxHq){ return BnITs[mkvls(EtPYBYPQMmKVk[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}