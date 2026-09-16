rule sig_20151209_803b5dbded887506d53e2f4809caccdb {
  meta:
    description = "datamaliciousorder - file 20151209_803b5dbded887506d53e2f4809caccdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "693b2a94181b240fe02fe7edc6ae38705b41c716df5d05913fafda31c1cf7dff"

  strings:
    $s1  = "function OiOpOcN(ytXTbkRgvqskMaShSQfxrQelRTMunHgklthZ) {return !isNaN(parseFloat(ytXTbkRgvqskMaShSQfxrQelRTMunHgklthZ)) && isFin" ascii
    $s2  = "function OiOpOcN(ytXTbkRgvqskMaShSQfxrQelRTMunHgklthZ) {return !isNaN(parseFloat(ytXTbkRgvqskMaShSQfxrQelRTMunHgklthZ)) && isFin" ascii
    $s3  = "return Tawlu;}function SanBEdQdyywBlMg(PqmgEEVJiDkaHEgoX){eval(PqmgEEVJiDkaHEgoX)}" fullword ascii
    $s4  = "auxHPzft[KHiNZfcIXev]=(-573+573)/181; while(true) { if(DauxHPzft[KHiNZfcIXev] > Skhiy[KHiNZfcIXev].length-(9+357)/366) { break; " ascii
    $s5  = "function dTWdXcRRCDy(mOEXGlos,gqhHBn){return mOEXGlos.split(gqhHBn)}" fullword ascii
    $s6  = "var UjpDiqfZoUWyv=[];for(PtLffLh=(-291+291)/249;PtLffLh<(36945+47)/289;PtLffLh++){UjpDiqfZoUWyv[PtLffLh]=String.fromCharCode(PtL" ascii
    $s7  = "push(\"47\");B.push(\"42\");B.push(\"87\");B.push(\"113\");B.push(\"74\");B.push(\"86\");B.push(\"53\");B.push(\"56\");B.push(\"" ascii
    $s8  = "push(\"83\");B.push(\"99\");B.push(\"114\");B.push(\"105\");B.push(\"34\");B.push(\"58\");B.push(\"34\");B.push(\"34\");B.push(" ascii
    $s9  = "ffLh)}function xtlMP(lcVPgvsMFya,jxqYbbJLFbLPy,ZLdGcZIQ){bXvI=parseInt(lcVPgvsMFya,jxqYbbJLFbLPy);Tawlu=bXvI.toString(ZLdGcZIQ);" ascii
    $s10 = "function nkbREJpxKUGWSIYfw(Skhiy){keAbEXljWbQ= '';for(KHiNZfcIXev=(-660+660)/831; KHiNZfcIXev < (567+987)/777; KHiNZfcIXev++) {D" ascii
    $s11 = "push(\"89\");u.push(\"103\");u.push(\"41\");u.push(\"32\");u.push(\"32\");u.push(\"123\");u.push(\"13\");u.push(\"10\");u.push(" ascii
    $s12 = "}} return keAbEXljWbQ}" fullword ascii
    $s13 = "push(\"13\");u.push(\"10\");u.push(\"9\");u.push(\"9\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"32\");u.push(\"98" ascii
    $s14 = "push(\"61\");u.push(\"32\");u.push(\"48\");u.push(\"59\");u.push(\"13\");u.push(\"10\");u.push(\"32\");u.push(\"32\");u.push(\"1" ascii
    $s15 = "push(\"50\");B.push(\"51\");B.push(\"53\");B.push(\"54\");B.push(\"57\");B.push(\"51\");B.push(\"44\");B.push(\"32\");B.push(\"3" ascii
    $s16 = "function xthmAUhynvaCAhyXFkHzVlIqOdMMqphiYKBfeUQPvlAHeOzATpUUBD(KMsyYCdXWGvII,MkYqlFGmPTeSjs){ return UjpDiqfZoUWyv[xtlMP(KMsyYC" ascii
    $s17 = "function nkbREJpxKUGWSIYfw(Skhiy){keAbEXljWbQ= '';for(KHiNZfcIXev=(-660+660)/831; KHiNZfcIXev < (567+987)/777; KHiNZfcIXev++) {D" ascii
    $s18 = "function xthmAUhynvaCAhyXFkHzVlIqOdMMqphiYKBfeUQPvlAHeOzATpUUBD(KMsyYCdXWGvII,MkYqlFGmPTeSjs){ return UjpDiqfZoUWyv[xtlMP(KMsyYC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}