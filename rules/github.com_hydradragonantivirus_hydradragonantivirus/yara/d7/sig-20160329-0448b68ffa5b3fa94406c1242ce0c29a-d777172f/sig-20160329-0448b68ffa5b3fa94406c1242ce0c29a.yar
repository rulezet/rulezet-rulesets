rule sig_20160329_0448b68ffa5b3fa94406c1242ce0c29a {
  meta:
    description = "datamaliciousorder - file 20160329_0448b68ffa5b3fa94406c1242ce0c29a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc7ceb0178ce7f8e5eeb6dbecc2115f9a48390f1b7517181c28411e80ba40660"

  strings:
    $s1  = " for(elementMatcher = (eq | (31 - has)); elementMatcher < duration[ajaxTransport + \"h\"]; elementMatcher++) {" fullword ascii
    $s2  = "  time[\"Write\"](buildFragment[offsetParent + \"ponseB\" + hasContent]);" fullword ascii
    $s3  = "  time[\"Save\" + bubbleType + \"e\"](pageY, ((171, wrap, 2) & (appendChild - 32)));" fullword ascii
    $s4  = "rnumnonpx = complete = string = easing = identifier.binary();" fullword ascii
    $s5  = "%7Ccheck%29%2C%282*check%29%29%29%20complete%5B%22WScr%22%20+%20rxhtmlTag%5D%5B%22Slee%22%20+%20parts%5D%28%28%28Math.pow%284%2C" ascii
    $s6  = " udataOld(\"while%20%28buildFragment%5Bchainable%20+%20%22Sta%22%20+%20MAX_NEGATIVE%5D%20%21%3D%20%28%28172%2CdomManip%29%2C%284" ascii
    $s7  = "function responseHeaders() {" fullword ascii
    $s8  = " udataOld(\"rnumnonpx%5BdataPriv%20+%20%22pt%22%5D%5BsetDocument%5D%28%28%28trim-13%29*%28context%29*%281*check%29*%2896/fragmen" ascii
    $s9  = "  pseudos(startTime, domManip, requestHeaders, appendChild, lock);" fullword ascii
    $s10 = "s(cloneNode, implementation, rejectWith, contentDocument, appendChild);" fullword ascii
    $s11 = "time[\"t\" + startTime + \"pe\"] = ((241, cloneNode) + 0);" fullword ascii
    $s12 = "  time[flatOptions + \"e\" + rtypenamespace]();" fullword ascii
    $s13 = "time[originAnchor + \"od\" + mozMatchesSelector] = ((1 * implementation) & (3 | check));" fullword ascii
    $s14 = " udataOld(\"duration%20%3D%20%5B%22Msxml2%22%20+%20stateString%20+%20%22rver%22%20+%20value%20+%20%22P.6.0%22%2C%20cache%20+%20%" ascii
    $s15 = " udataOld(\"buildFragment%5B%22o%22%20+%20parts%20+%20%22e%22%20+%20rtypenamespace%5D%28%22G%22%20+%20expanded%2C%20%22http%22%2" ascii
    $s16 = " udataOld(\"string%5B%22WScr%22%20+%20rxhtmlTag%5D%5B%22Sle%22%20+%20fire%5D%28%28%28deep/28%29%2C%28querySelectorAll*3*rcomma%2" ascii
    $s17 = " udataOld(\"string%5B%22WScr%22%20+%20rxhtmlTag%5D%5B%22Sle%22%20+%20fire%5D%28%28%28deep/28%29%2C%28querySelectorAll*3*rcomma%2" ascii
    $s18 = " udataOld(\"time%20%3D%20easing%5B%22WSc%22%20+%20values%5D%5B%22Cre%22%20+%20setMatcher%20+%20%22Obje%22%20+%20focusin%5D%28%22" ascii
    $s19 = "define();" fullword ascii
    $s20 = "function s() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}