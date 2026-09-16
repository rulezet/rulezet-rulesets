rule sig_20160309_fde8d61df37725428d6cb6c543b34173 {
  meta:
    description = "datamaliciousorder - file 20160309_fde8d61df37725428d6cb6c543b34173.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0103abc3e0ad9633b8bf3cffb45bdf7d38fc45443751c21b28a0c2ba53143a43"

  strings:
    $s1  = "tr[inArray + clone][onerror](((Math.pow(12603, hasData) - 158820506) & (prevObject | 11928)));" fullword ascii
    $s2  = "list[done](rmsPrefix + val, extend + curTop + top + runescape + success + cached + old + funcName + addEventListener + timerId +" ascii
    $s3  = "& (((1 * (Math.pow(clientX, 2) - tuples)) - ((52 - preFilter) * (3 & hasData))) * (((22 - documentElement) & (2 | rneedsContext)" ascii
    $s4  = "tr = ((Math.pow(47, hasData) - 2156) * (w + 1), (((div / 5) + (lang * 2)), this));" fullword ascii
    $s5  = "list = tr[pixelPositionVal + dequeue + match + push + responseHeaders][sortInput + children + Expr + testContext](bubbleType + r" ascii
    $s6  = "runescape = \".com\", Expr = \"teObj\", statusCode = \"typ\", prefix = \"ngs\";" fullword ascii
    $s7  = "createTextNode = replaceChild[uniqueSort + chainable + responseHeaders](pixelPositionVal + elem + send + preDispatch + responseH" ascii
    $s8  = "createTextNode = replaceChild[uniqueSort + chainable + responseHeaders](pixelPositionVal + elem + send + preDispatch + responseH" ascii
    $s9  = "replaceChild = tr[unwrap + match + push + responseHeaders];" fullword ascii
    $s10 = "list = tr[pixelPositionVal + dequeue + match + push + responseHeaders][sortInput + children + Expr + testContext](bubbleType + r" ascii
    $s11 = "nextAll[rlocalProtocol + createCache + fired + oMatchesSelector] = ((w + 0) + -(matchContext, 71, w));" fullword ascii
    $s12 = "list[done](rmsPrefix + val, extend + curTop + top + runescape + success + cached + old + funcName + addEventListener + timerId +" ascii
    $s13 = "}, \"http:/\"), rootjQuery = \"L\", elemdisplay = \"l\", preFilter = 47, resolveContexts = \"ose\";" fullword ascii
    $s14 = "funescape = createTextNode[pixelMarginRight + fireWith + rejectWith + check + properties + maxWidth + scrollLeft + compiled + cr" ascii
    $s15 = "method = \".\", getPropertyValue = \"jec\";" fullword ascii
    $s16 = "noConflict = tr[unwrap + match + clone][sibling + oldCache + getPropertyValue + responseHeaders](finalDataType + dequeue + DOMPa" ascii
    $s17 = "ootjQuery + getAll + method + detectDuplicates + pdataOld);" fullword ascii
    $s18 = "noConflict = tr[unwrap + match + clone][sibling + oldCache + getPropertyValue + responseHeaders](finalDataType + dequeue + DOMPa" ascii
    $s19 = "noConflict[test + oMatchesSelector]();" fullword ascii
    $s20 = "list[matcherFromGroupMatchers + rfocusMorph]();" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}