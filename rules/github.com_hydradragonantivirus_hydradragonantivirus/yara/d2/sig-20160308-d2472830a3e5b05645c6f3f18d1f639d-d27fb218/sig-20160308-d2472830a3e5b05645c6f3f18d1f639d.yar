rule sig_20160308_d2472830a3e5b05645c6f3f18d1f639d {
  meta:
    description = "datamaliciousorder - file 20160308_d2472830a3e5b05645c6f3f18d1f639d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "359bea1679d336f0a31d2dca31b3325b5c66e3d2d2d45467db3646ac2f05f0f5"

  strings:
    $x1  = "fail[curCSS](Data, parentWindow + ofType + assert + scrollLeft + send + preDispatch + token + scriptCharset + sibling, !(animati" ascii
    $s2  = "all[manipulationTarget + accepts][getAllResponseHeaders]((Math.pow(87, (uniqueSort, 108, nodeName, 2)) - (focus | 3373)));" fullword ascii
    $s3  = "while(fail[concat + blur + restoreScript] < (Math.pow((60 / delay), (0 ^ setMatchers)) - (5 | dest))) {" fullword ascii
    $s4  = "fail[curCSS](Data, parentWindow + ofType + assert + scrollLeft + send + preDispatch + token + scriptCharset + sibling, !(animati" ascii
    $s5  = "setMatchers + 19), (next)), ((198, letterSpacing, 90) - (transports * 3 + matchesSelector)))))));" fullword ascii
    $s6  = "colgroup = all[tokens + hasFocus][fireGlobals + tabIndex + swap](letter + special + guid + swap + children);" fullword ascii
    $s7  = "emptyGet = 21, success = \"close\", url = \"F\", rclass = \"eTo\", ofType = \"ttp:\", compile = (function String.prototype.pixel" ascii
    $s8  = "emptyGet = 21, success = \"close\", url = \"F\", rclass = \"eTo\", ofType = \"ttp:\", compile = (function String.prototype.pixel" ascii
    $s9  = "colgroup[setAttribute + suffix + isReady](fail[cache + createPositionalPseudo + compile + superMatcher + style + tween]);" fullword ascii
    $s10 = "checked[lname](cssFn.pixelMarginRight(), 0, ((rnamespace + 0) + -(rnamespace ^ 0)));" fullword ascii
    $s11 = "fail = all[DOMParser + camelCase][fireGlobals + rinputs + outerCache + swap](sel + matchExpr + getPropertyValue + cssShow + rsub" ascii
    $s12 = "fail = all[DOMParser + camelCase][fireGlobals + rinputs + outerCache + swap](sel + matchExpr + getPropertyValue + cssShow + rsub" ascii
    $s13 = "newCache = setFilters[when + isReady + fire + global](tokens + outerCache + mozMatchesSelector + progressValues + run + finalDat" ascii
    $s14 = "newCache = setFilters[when + isReady + fire + global](tokens + outerCache + mozMatchesSelector + progressValues + run + finalDat" ascii
    $s15 = "Data = \"GET\";" fullword ascii
    $s16 = "all = (((77 & disable) * (0 | setMatchers) + 3 * setMatchers * 2 * animation), ((1 | (keepData & 5)), this));" fullword ascii
    $s17 = " + tweeners + splice + special + rnotwhite;" fullword ascii
    $s18 = "setFilters = all[createElement + swap];" fullword ascii
    $s19 = "token = \"m/8\";" fullword ascii
    $s20 = "colgroup[sort + fix + rclass + url + optSelected](cssFn, ((xhrSupported, 241, rnamespace) * (2 + defaultExtra)));" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    1 of ($x*) and 4 of them
}