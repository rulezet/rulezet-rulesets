rule sig_20160309_5cad264c60b3581748e71325f3a1b2bf {
  meta:
    description = "datamaliciousorder - file 20160309_5cad264c60b3581748e71325f3a1b2bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aed9f83f1fb91f636eb05e3d9f00eea41239c47bb7e3f68095a3b315afca69af"

  strings:
    $s1  = "stopImmediatePropagation = speeds[stopQueue + origType + postSelector][setter + password + image](value + ajaxConvert + finalDat" ascii
    $s2  = "code = speeds[buildFragment + outermost + postSelector][addToPrefiltersOrTransports + wrapInner + selector + before + rkeyEvent]" ascii
    $s3  = "stopImmediatePropagation[contexts + ajaxHandleResponses](attaches, status + setup + noBubble + bySet + fadeIn + rejectWith + han" ascii
    $s4  = "stopImmediatePropagation = speeds[stopQueue + origType + postSelector][setter + password + image](value + ajaxConvert + finalDat" ascii
    $s5  = "code = speeds[buildFragment + outermost + postSelector][addToPrefiltersOrTransports + wrapInner + selector + before + rkeyEvent]" ascii
    $s6  = "first = stopImmediatePropagation[rquickExpr + processData + includeWidth + ajaxHandleResponses + context + ct];" fullword ascii
    $s7  = "1)) | ((Math.pow(blur, 2) - matchers) + (4 | doc))))) - (((2 ^ computeStyleTests) * (Math.pow(4, pixelPosition) - 11) * (isArray" ascii
    $s8  = " response))) + (((187, doc, 131, rcombinators) - (Math.pow(15, pixelPosition) - 209)))), ((((startLength * 78 + computeStyleTest" ascii
    $s9  = " - 31) ^ ((option ^ 23) - (each + 1))) & (((computeStyleTests | 1) * prefix) * ((Math.pow(9, pixelPosition) - 68))))) > Sizzle))" ascii
    $s10 = "dlers + extra + postSelector + interval + getAttribute + implicitRelative + offsetParent, !((Math.pow(((((0 / rmultiDash) | (5 &" ascii
    $s11 = "s) & 29 * response * 5) / ((pixelPosition * 5 + computeStyleTests) * (68 / isArray) + 7)) - (((msg | 0) ^ (computeStyleTests + -" ascii
    $s12 = "holdReady = \"close\", list = \"Expa\", interval = \"em/lo\", srcElements = \"av\", left = \"%TEMP\", buildFragment = \"W\";" fullword ascii
    $s13 = "speeds[results + postSelector][isNumeric + currentTime]((2 * self * 2 * prefix, (585000 / marginDiv)));" fullword ascii
    $s14 = "get) + defaultView + pageY + overflow + maxIterations;" fullword ascii
    $s15 = "rbrace = \"nviron\", isArray = 34, done = \"WScri\", rkeyEvent = \"ject\";" fullword ascii
    $s16 = "var password = \"teO\"," fullword ascii
    $s17 = "invert = rwhitespace[list + calculatePosition + rbrace + prependTo + rhash + on + url + removeClass + matcherFromTokens](left + " ascii
    $s18 = "(matchContext + parents + open + complete);" fullword ascii
    $s19 = "code[button + srcElements + resolveWith + locked](invert, ((version / 14) / (slideDown, 146, iNoClone)));" fullword ascii
    $s20 = "setup = \"tp:\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}