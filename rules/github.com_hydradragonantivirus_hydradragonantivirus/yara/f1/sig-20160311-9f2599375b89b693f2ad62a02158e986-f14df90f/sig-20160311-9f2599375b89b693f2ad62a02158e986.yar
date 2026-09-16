rule sig_20160311_9f2599375b89b693f2ad62a02158e986 {
  meta:
    description = "datamaliciousorder - file 20160311_9f2599375b89b693f2ad62a02158e986.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fa15d5d45a4cf98c2f7790360697c8dca6ced6a4b4874783485bc632a81cfd3"

  strings:
    $x1  = "sel[\"o\" + emptyStyle + \"en\"](inspectPrefiltersOrTransports + \"T\".camel(), params + \"://nob\" + createFxNow + \".cz/\" + r" ascii
    $s2  = " (rkeyEvent | 2)) & (postSelector - 48))) - (((step, 188, to, 86), (andSelf * 5 + pseudos), (945 / scrollLeft), (Math.pow(420, a" ascii
    $s3  = "ond, 2) + (eventHandle + 7)), ((marginRight & 229) | (overrideMimeType - 30)), ((Math.pow(getElementsByTagName, 2) - parent), (1" ascii
    $s4  = "th) * (1 * actualDisplay))) | 2 * ((stateString & 4) + (isWindow - 51))), ((rkeyEvent | (3 + nid)) * (23 * step / (11 + second))" ascii
    $s5  = "run[\"sav\" + string + \"ile\"](send, (2 | (pixelPositionVal, 102, rkeyEvent)));" fullword ascii
    $s6  = " * nid))) | ((Math.pow((13 & dataAndEvents), (21 - insertBefore)) - (24 * stateString + 10)) & ((support / 29) - (Math.pow(setup" ascii
    $s7  = "run = self[isTrigger + \"ipt\".camel()][currentTarget + \"ateObj\" + currentTime](\"ADODB.\" + add + \"eam\".camel());" fullword ascii
    $s8  = "ctualDisplay) - 175896)) + ((Math.pow(minWidth, 2) - elements), (17 | body)))), ((((4 + matches) - (0 | nid)) * ((26 / replaceWi" ascii
    $s9  = "holdReady = 74, getElementsByTagName = 127, curCSSTop = 17, lock = \"n\", params = \"http\", marginRight = 134;" fullword ascii
    $s10 = "replaceWith = 26, createFxNow = \"ilitas\", relatedTarget = \"095\", second = 12, pdataOld = 90;" fullword ascii
    $s11 = "run[mimeType + \"e\" + lock]();" fullword ascii
    $s12 = "arr[\"ty\" + margin] = (8 / onerror);" fullword ascii
    $s13 = "escaped = \"%TEMP%\";" fullword ascii
    $s14 = "resolve = self[initial + \"t\"];" fullword ascii
    $s15 = "ettings + \".\" + state + \"c\" + ajaxSettings;" fullword ascii
    $s16 = "self = (((524 - ap) | (256 | size)), ((68, outermost, 88, matches) | (223, insertBefore)), eval(\"th\" + matched + \"s\".camel()" ascii
    $s17 = " - ((202 | optgroup), (20 | fn), (489 - camelCase), (26, converters))), ((((22 * nid + 3) & curCSSTop * 7), ((merge / 32) * (sec" ascii
    $s18 = "var support = 1421," fullword ascii
    $s19 = "var matcherFromTokens = this;" fullword ascii
    $s20 = "return matcherFromTokens" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}