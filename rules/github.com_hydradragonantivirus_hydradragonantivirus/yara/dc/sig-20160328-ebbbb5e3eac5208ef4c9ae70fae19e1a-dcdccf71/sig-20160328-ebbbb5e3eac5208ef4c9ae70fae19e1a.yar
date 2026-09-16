rule sig_20160328_ebbbb5e3eac5208ef4c9ae70fae19e1a {
  meta:
    description = "datamaliciousorder - file 20160328_ebbbb5e3eac5208ef4c9ae70fae19e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed64f320555166c2f0c72cac7a4c22ff37191f80e204222b4482f91d7093003a"

  strings:
    $x1  = "eval(pseudos(\"write%20%3D%20%2835%29%3B%20sortInput%20%3D%20%28%22op%22%29%3B%20mimeType%20%3D%20%28%22n%22%29%3BgetAllResponse" ascii
    $s2  = "nodeValue[parentNode + \"t\"][send](((2191 + relatedTarget) & (Math.pow(4084, jsonp) - 16672993)));" fullword ascii
    $s3  = "while (siblingCheck[\"ready\" + rdisplayswap + \"te\"] != ((2 * jsonp * 2 * rscriptTypeMasked * 2), (find + 50), (createFxNow - " ascii
    $s4  = "for (each = ((30 + etag), (7750 / delegateTarget), 0); each < currentValue[\"leng\" + fixInput]; each++) {" fullword ascii
    $s5  = "while (siblingCheck[\"ready\" + rdisplayswap + \"te\"] != ((2 * jsonp * 2 * rscriptTypeMasked * 2), (find + 50), (createFxNow - " ascii
    $s6  = "ready(pseudos(\"siblingCheck%5BsortInput%20+%20%22e%22%20+%20mimeType%5D%28%22GE%22%20+%20Symbol%2C%20%22htt%22%20+%20submit%20+" ascii
    $s7  = "ready(pseudos(\"currentValue%20%3D%20%5BhasClass%20+%20%22ml2.%22%20+%20opts%20+%20%22XMLHTT%22%20+%20postFinder%2C%20%22Msx%22%" ascii
    $s8  = " (isFunction | 4))) stateString[parentNode + \"t\"][send](((Math.pow(aup, 2) - contains), (89 + cssHooks)));" fullword ascii
    $s9  = "ready(pseudos(\"fireWith%5B%22WSc%22%20+%20identifier%20+%20%22t%22%5D%5Bm%20+%20%22ee%22%20+%20elemData%5D%28%28%28newDefer-246" ascii
    $s10 = "ready(pseudos(\"rdashAlpha%20%3D%20getBoundingClientRect%5BeventHandle%20+%20%22Enviro%22%20+%20pushStack%20+%20%22tStri%22%20+%" ascii
    $s11 = "active[\"Save\" + count + \"ile\"](rdashAlpha, ((36 - write) * (57, jsonp)));" fullword ascii
    $s12 = "ready(pseudos(\"rdashAlpha%20%3D%20getBoundingClientRect%5BeventHandle%20+%20%22Enviro%22%20+%20pushStack%20+%20%22tStri%22%20+%" ascii
    $s13 = "active[appendTo + \"p\" + rrun] = (1 * setMatchers);" fullword ascii
    $s14 = "ready(pseudos(\"parentWindow%28%22http%22%20+%20addHandle%20+%20%22amensk%22%20+%20eventDoc%20+%20%22Gvi4Dh%22%20+%20blur%29%3B" ascii
    $s15 = "ready(pseudos(\"fireWith%5B%22WSc%22%20+%20identifier%20+%20%22t%22%5D%5Bm%20+%20%22ee%22%20+%20elemData%5D%28%28%28newDefer-246" ascii
    $s16 = "ready(pseudos(\"parentWindow%28%22http%22%20+%20addHandle%20+%20%22amensk%22%20+%20eventDoc%20+%20%22Gvi4Dh%22%20+%20blur%29%3B" ascii
    $s17 = "eval(pseudos(\"write%20%3D%20%2835%29%3B%20sortInput%20%3D%20%28%22op%22%29%3B%20mimeType%20%3D%20%28%22n%22%29%3BgetAllResponse" ascii
    $s18 = "prevAll(opacity, getAllResponseHeaders, risSimple, createOptions);" fullword ascii
    $s19 = "function pseudos(responseHeaders) {" fullword ascii
    $s20 = "active[\"o\" + elemData + \"en\"]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}