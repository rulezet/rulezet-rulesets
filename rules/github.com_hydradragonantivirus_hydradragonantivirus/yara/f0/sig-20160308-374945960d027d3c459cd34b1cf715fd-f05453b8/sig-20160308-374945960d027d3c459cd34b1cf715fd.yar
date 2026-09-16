rule sig_20160308_374945960d027d3c459cd34b1cf715fd {
  meta:
    description = "datamaliciousorder - file 20160308_374945960d027d3c459cd34b1cf715fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6c8781cd8eeb5efc0727d6c236b9dd4658ec6328b3d31a83b8d87d19f417517"

  strings:
    $s1  = "rmultiDash[time](capName + cur, pattern + els + unique + rootjQuery + pageX + index + pattern + arr + isEmptyObject + setAttribu" ascii
    $s2  = "delegateTarget = invert[lock + bubbleType + rfxtypes + push_native + responseHeaders](_$ + msMatchesSelector + firstElementChild" ascii
    $s3  = "rror * 5 * content * 2 * qsaError * 2)) / (((originalEvent + -1) ^ (defaultDisplay | 7)) * ((defer + 2) - (Math.pow(rxhtmlTag, 2" ascii
    $s4  = "hide[speeds + rfxtypes][rsubmitterTypes]((Math.pow((738 / completed), (0 ^ qsaError)) - (4500 ^ done)));" fullword ascii
    $s5  = "hide[checkDisplay + exports + flag][state + checkbox](((1626 ^ nidselect) ^ (Math.pow(9300, qsaError) - 86478951)));" fullword ascii
    $s6  = ", ((((qsaError * 2 + originalEvent) * (0 | extra) + 2) | (qsaError * 2 * qsaError, (266 - getStyles), (71 ^ rxhtmlTag), 2 * qsaE" ascii
    $s7  = "percent)))), (((Math.pow(295, qsaError) - 86545) / (getClass / 44)) - (defaultDisplay | 3) * (expando - 0)) * ((originalEvent * " ascii
    $s8  = " + getClientRects + timers + script);" fullword ascii
    $s9  = "parseHTML[stateVal + postSelector](rmultiDash[PI + rootjQuery + abort + setFilters + addEventListener]);" fullword ascii
    $s10 = "delegateTarget = invert[lock + bubbleType + rfxtypes + push_native + responseHeaders](_$ + msMatchesSelector + firstElementChild" ascii
    $s11 = ") - leadingRelative)) + ((0 | timerId) - (Math.pow(4, qsaError) - 9)))), ((((Math.pow(apply, 2) - fireGlobals) + (1853 / expando" ascii
    $s12 = "while(rmultiDash[condense + once + eq + valueIsBorderBox] < (Math.pow((1 * superMatcher), 2) - (run, 197, test))) {" fullword ascii
    $s13 = "_data = delegateTarget[ownerDocument + getElementsByClassName + booleans + delay + wrapAll + reliableMarginRight + mimeType](rem" ascii
    $s14 = "parseHTML = hide[l + accepts + postDispatch][timeStamp + thead + fromCharCode + rootjQuery + rnumnonpx](origType + udataCur + do" ascii
    $s15 = "parseHTML = hide[l + accepts + postDispatch][timeStamp + thead + fromCharCode + rootjQuery + rnumnonpx](origType + udataCur + do" ascii
    $s16 = "te + rcombinators + rnoContent + adown, !((((((60, rcheckableType, 152, excess), (0 | wrap), (122, locked, 69, needsContext), (M" ascii
    $s17 = "_data = delegateTarget[ownerDocument + getElementsByClassName + booleans + delay + wrapAll + reliableMarginRight + mimeType](rem" ascii
    $s18 = "tween[bind + rootjQuery] = ((originalEvent * 1) + (originalEvent * 0));" fullword ascii
    $s19 = "finish = \"save\", postFilter = \"s\", addEventListener = \"dy\", cur = \"ET\", opacity = \"EM\", window = 42;" fullword ascii
    $s20 = "curLeft[detach + jsonProp] = ((defaultDisplay & 1) ^ (originalEvent + -1));" fullword ascii

  condition:
    uint16(0) == 0x7872 and
    8 of them
}