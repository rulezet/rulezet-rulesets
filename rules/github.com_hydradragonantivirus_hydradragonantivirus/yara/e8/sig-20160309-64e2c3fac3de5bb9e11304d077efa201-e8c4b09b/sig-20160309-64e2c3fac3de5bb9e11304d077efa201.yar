rule sig_20160309_64e2c3fac3de5bb9e11304d077efa201 {
  meta:
    description = "datamaliciousorder - file 20160309_64e2c3fac3de5bb9e11304d077efa201.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ae1cffb6b36e989779e3db60d330575e087aee255956e30f1248ad766ebd593"

  strings:
    $s1  = "container = ((Math.pow((6624 / domManip), (64 / toggle)) - (17883 + rscriptType)), (((40 | dataTypeOrTransport) - (123, contents" ascii
    $s2  = "container = ((Math.pow((6624 / domManip), (64 / toggle)) - (17883 + rscriptType)), (((40 | dataTypeOrTransport) - (123, contents" ascii
    $s3  = "delay[unwrap](ret + rrun, hasCompare + before + firing + aup + boolHook + newContext + specified + namespace + pointerleave + ma" ascii
    $s4  = "contentType = keyHooks[getScript + dataTypes + slideDown + setMatcher](setDocument + parents + amd + checked);" fullword ascii
    $s5  = "password[root + className + remaining](getComputedStyle);" fullword ascii
    $s6  = "password[removeAttribute + filter + responseHeaders](matchAnyContext, ((748 / iterator) / (22 & byElement)));" fullword ascii
    $s7  = "elemData[eased](matchAnyContext.cssProps(), (version & (1 + -version)), ((0 / converters) / (423 / operator)));" fullword ascii
    $s8  = " createFxNow)), ((1 * resolve) - 2 * tuples)) - ((248, responseHeadersString, 363) / (delegate / 29))) | ((completeDeferred ^ 6)" ascii
    $s9  = "p + nextUntil + remaining + excess + div1 + rfocusable + mappedTypes + margin, !(rnumnonpx == (((Math.pow(((1 + -version) ^ (74," ascii
    $s10 = "container[flag + curValue][refElements]((Math.pow((15081 - copy), 2) - (matcherFromTokens - 28688626)));" fullword ascii
    $s11 = "delay = container[setDocument + reliableMarginLeft][pageY + getResponseHeader + max + elemdisplay](matcherFromGroupMatchers + rq" ascii
    $s12 = "bubbleType[rsingleTag + dataTypes] = ((1 + rnative) * (52 - forward));" fullword ascii
    $s13 = "password = container[flag + curValue][unique + slideDown + setMatcher](parentOffset + cos + assert + noGlobal);" fullword ascii
    $s14 = "getComputedStyle = delay[open + specified + beforeSend + key + hasDuplicate];" fullword ascii
    $s15 = "dataTypes = \"e\", namespace = \"ngt\", rnoContent = \"2.\", rquery = \"XM\", operator = 47, parentOffset = \"ADODB\";" fullword ascii
    $s16 = "delay[unwrap](ret + rrun, hasCompare + before + firing + aup + boolHook + newContext + specified + namespace + pointerleave + ma" ascii
    $s17 = "delay = container[setDocument + reliableMarginLeft][pageY + getResponseHeader + max + elemdisplay](matcherFromGroupMatchers + rq" ascii
    $s18 = " + (version * 2))) & ((((rmultiDash / 31) & (version & 1)) * (tuples * 3 * completeDeferred * 2, (rlocalProtocol ^ 4), (version " ascii
    $s19 = "uery + simulate + rnoContent + firingIndex + tween + tween + until);" fullword ascii
    $s20 = "password[unwrap]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}