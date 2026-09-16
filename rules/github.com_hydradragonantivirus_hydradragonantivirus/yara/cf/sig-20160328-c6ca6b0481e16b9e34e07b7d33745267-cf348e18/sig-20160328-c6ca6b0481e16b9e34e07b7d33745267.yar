rule sig_20160328_c6ca6b0481e16b9e34e07b7d33745267 {
  meta:
    description = "datamaliciousorder - file 20160328_c6ca6b0481e16b9e34e07b7d33745267.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb770de2d3fa4fffc4610284e6ba3602d42431bcabe21f1b7170140eb09807e2"

  strings:
    $s1  = "while(hasDuplicate[\"rea\" + seekingTransport + \"ate\"] != ((letterSpacing + 1) + (uniqueID - 44))) letter[delegateTarget + \"i" ascii
    $s2  = "while(hasDuplicate[\"rea\" + seekingTransport + \"ate\"] != ((letterSpacing + 1) + (uniqueID - 44))) letter[delegateTarget + \"i" ascii
    $s3  = "operator(MAX_NEGATIVE, relatedTarget);" fullword ascii
    $s4  = "setDocument[\"mo\" + getWidthOrHeight] = (3 & (prop - 32));" fullword ascii
    $s5  = "split + \"eep\"](((Math.pow(fxNow, 2) - sortInput) / (55 - responseText)));" fullword ascii
    $s6  = "target(cssShow, firstElementChild);" fullword ascii
    $s7  = "function target(attachEvent, doAnimation) {" fullword ascii
    $s8  = "fore%20%3D%20%28%22pt%22%29%2C%20contentType%20%3D%20%28%22Oy.%22%29%2C%20setGlobalEval%20%3D%20%288%29%2C%20tmp%20%3D%20%28%222" ascii
    $s9  = "function operator(overwritten, addToPrefiltersOrTransports, stop) {" fullword ascii
    $s10 = "tween(udataCur(\"buildFragment%20%3D%20%5B%22Msxml%22%20+%20tmp%20+%20%22erverX%22%20+%20pnum%20+%20%22TTP.%22%20+%20parsed%2C%2" ascii
    $s11 = "tween(udataCur(\"hasDuplicate%5B%22op%22%20+%20show%5D%28%22G%22%20+%20createHTMLDocument%20+%20%22T%22%2C%20ajaxConvert%20+%20%" ascii
    $s12 = "tween(udataCur(\"fnOver%28ajaxConvert%20+%20%22%3A//4%22%20+%20rpseudo%20+%20%22utt%22%20+%20stored%20+%20%22al.c%22%20+%20secon" ascii
    $s13 = "letter = trigger = qsa = getElementById = doScroll.invert();" fullword ascii
    $s14 = "function gotoEnd(getAttributeNode, stopQueue, isHidden) {" fullword ascii
    $s15 = "setDocument[extra + \"en\"]();" fullword ascii
    $s16 = "for(contains = ((close + 8) - (maxIterations & 47)); contains < buildFragment[callbackInverse + \"h\"]; contains++) {" fullword ascii
    $s17 = "function bubbleType(contexts, firing, tokenize) {" fullword ascii
    $s18 = "tween(udataCur(\"buildFragment%20%3D%20%5B%22Msxml%22%20+%20tmp%20+%20%22erverX%22%20+%20pnum%20+%20%22TTP.%22%20+%20parsed%2C%2" ascii
    $s19 = "Crea%22%29%2C%20responseText%20%3D%20%2821%29%3BseekingTransport%20%3D%20%28%22dySt%22%29%3B%20backgroundClip%20%3D%20%286%29%3B" ascii
    $s20 = "tween(udataCur(\"rparentsprev%20%3D%20callbackExpect%5BcurrentValue%20+%20%22Enviro%22%20+%20preFilters%20+%20%22Strin%22%20+%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}