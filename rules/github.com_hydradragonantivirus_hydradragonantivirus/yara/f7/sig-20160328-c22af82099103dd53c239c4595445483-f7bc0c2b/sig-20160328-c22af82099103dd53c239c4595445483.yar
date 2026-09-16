rule sig_20160328_c22af82099103dd53c239c4595445483 {
  meta:
    description = "datamaliciousorder - file 20160328_c22af82099103dd53c239c4595445483.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc747fadb4d522a871d5515a39e231417584703dead2590b4d4c1b56d89c9122"

  strings:
    $s1  = "   while (rkeyEvent[removeChild + \"dySta\" + scripts] != (Math.pow((1 + fixHook), (2 | Sizzle)) - (Math.pow(4, fixHook) - 11)))" ascii
    $s2  = "   while (rkeyEvent[removeChild + \"dySta\" + scripts] != (Math.pow((1 + fixHook), (2 | Sizzle)) - (Math.pow(4, fixHook) - 11)))" ascii
    $s3  = "[\"WSc\" + toggle][\"Sleep\"](((Math.pow(requestHeadersNames, 2) - fadeOut) - (18 * defaultExtra + 3)));" fullword ascii
    $s4  = "   if (rkeyEvent[oldfire + \"atu\" + value] == ((Math.pow(parseJSON, 2) - replaceAll) / (12 + Sizzle))) {" fullword ascii
    $s5  = "         rkeyEvent = collection[\"WScrip\" + timeoutTimer][\"Cre\" + expanded + \"ect\"](addEventListener[binary]);" fullword ascii
    $s6  = "elect%5D%28%22%25TEMP%25%22%20+%20animated%29%20+%20%22rdis%22%20+%20el%20+%20%22wap%22%20+%20sortInput%20+%20%22s%22%20+%20prop" ascii
    $s7  = "         rkeyEvent[value + \"e\" + superMatcher + \"d\"]();" fullword ascii
    $s8  = "collection = namespace = a = parentOffset = hasScripts.setPositiveNumber();" fullword ascii
    $s9  = "   for (binary = ((222, checkOn, 123), (animate + 1), (Sizzle & 0)); binary < addEventListener[\"lengt\" + first]; binary++) {" fullword ascii
    $s10 = "      inArray[\"R\" + focus](postMap);" fullword ascii
    $s11 = "function readyWait(setDocument, border, conv2) {" fullword ascii
    $s12 = "function newContext() {" fullword ascii
    $s13 = "function before() {" fullword ascii
    $s14 = "function tr() {" fullword ascii
    $s15 = "function msFullscreenElement() {" fullword ascii
    $s16 = "Name%3B\"));" fullword ascii
    $s17 = "function href(err, open) {" fullword ascii
    $s18 = "Display%2C%20%22Micr%22%20+%20cssFn%20+%20%22XMLHTT%22%20+%20fnOver%5D%3B\"));" fullword ascii
    $s19 = "function properties(props, checked) {" fullword ascii
    $s20 = "href(toggle);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}