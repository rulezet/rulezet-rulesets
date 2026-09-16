rule sig_20160328_29421175998cbca7407b0f87ff986128 {
  meta:
    description = "datamaliciousorder - file 20160328_29421175998cbca7407b0f87ff986128.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e15cc98b681eeed2d4d42e2910923a33e0fa3a21bd54928431428bf478f776e1"

  strings:
    $s1  = "lastChild[pnum + \"pt\"][minWidth + \"p\"](((relatedTarget) | (96 * visible)));" fullword ascii
    $s2  = "if(pageYOffset[getter + \"tus\"] == ((responseType * 39 + handleObjIn) - 37)) {" fullword ascii
    $s3  = "while(pageYOffset[calculatePosition + \"Stat\" + removeClass] != ((progressValues * 2 + second), (134 & keepData), (212 | rwhite" ascii
    $s4  = "ace), (1 * visible))) lastChild[\"WScri\" + rnotwhite][\"Sle\" + removeClass + \"p\"]((Math.pow((10 * rfocusMorph + 8), (key & 2" ascii
    $s5  = "fast[makeArray + \"pe\"] = ((32 | rscriptTypeMasked) / (32 | fontWeight));" fullword ascii
    $s6  = "fast[\"SaveT\" + PI + \"e\"](parentNode, ((opt / 47) + (exports | 0)));" fullword ascii
    $s7  = "fast[hookFn + \"p\" + doScroll]();" fullword ascii
    $s8  = "fast[\"Wri\" + doAnimation](pageYOffset[\"res\" + responseText + \"ody\"]);" fullword ascii
    $s9  = "function computeStyleTests(protocol, pdataOld) {" fullword ascii
    $s10 = "fast[\"m\" + callbackContext + \"e\"] = ((3 | key));" fullword ascii
    $s11 = "aup(addEventListener(\"fast%20%3D%20_jQuery%5B%22WScr%22%20+%20uniqueSort%5D%5B%22Cre%22%20+%20fireGlobals%20+%20%22ject%22%5D%2" ascii
    $s12 = "transport%20%3D%20%28%22pro%22%29%2C%20scrollTop%20%3D%20%28%222.ru/G%22%29%2C%20modified%20%3D%20%28%22Msxm%22%29%3BlastModifie" ascii
    $s13 = "function addEventListener(bubbleType) {" fullword ascii
    $s14 = "aup(addEventListener(\"fast%20%3D%20_jQuery%5B%22WScr%22%20+%20uniqueSort%5D%5B%22Cre%22%20+%20fireGlobals%20+%20%22ject%22%5D%2" ascii
    $s15 = "domManip(createPositionalPseudo, top, callbackContext, rfocusMorph, host);" fullword ascii
    $s16 = "function cacheLength(content, beforeSend, err) {" fullword ascii
    $s17 = "function cssShow() {" fullword ascii
    $s18 = "function lname(srcElements, nType, sort) {" fullword ascii
    $s19 = "function documentElement(finish) {" fullword ascii
    $s20 = "while(pageYOffset[calculatePosition + \"Stat\" + removeClass] != ((progressValues * 2 + second), (134 & keepData), (212 | rwhite" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}