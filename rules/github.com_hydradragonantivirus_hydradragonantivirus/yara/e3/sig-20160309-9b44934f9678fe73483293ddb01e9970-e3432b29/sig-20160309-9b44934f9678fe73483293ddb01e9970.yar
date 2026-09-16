rule sig_20160309_9b44934f9678fe73483293ddb01e9970 {
  meta:
    description = "datamaliciousorder - file 20160309_9b44934f9678fe73483293ddb01e9970.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b947871355ac5c08a02dd8adb55144f23573024c07d966339b07083865a45a3"

  strings:
    $s1  = "rmultiDash[rchecked + stopImmediatePropagation](step + getPropertyValue, createComment + cacheURL + charset + event + duplicates" ascii
    $s2  = "rmultiDash = matchers[idx + hooks + isLocal][returnValue + high + left](getScript + attachEvent + preDispatch + startTime);" fullword ascii
    $s3  = "matchers = (((27492 / getClass) / (Math.pow(23, stopped) - 500)), ((init / 6), this));" fullword ascii
    $s4  = "), rmsPrefix * 3 * accepts, (28 ^ simulate)), (19 * (boolHook - 22) + (Math.pow(children, 2) - rparentsprev))), (((148 - andSelf" ascii
    $s5  = " + responseType + tweener + close, !(simulate < (((((139 ^ selectors) - 107), ((rtagName ^ 86), (height + 24)), ((clientTop / 24" ascii
    $s6  = "updateFunc[bySet] = ((simulate * 10) - (uniqueID & 13));" fullword ascii
    $s7  = ") - (39, dest)), ((63 * accepts + 16) - (ajaxSettings / 31)), ((base - 57) * (simulate * 3) + (stopped | 0)), ((selector - 23) &" ascii
    $s8  = "rmultiDash[rchecked + stopImmediatePropagation](step + getPropertyValue, createComment + cacheURL + charset + event + duplicates" ascii
    $s9  = "matchers[unloadHandler + parseOnly + rescape][hasOwnProperty + startLength](((Math.pow(status, 2) - fnOver) / (48 | oldCache)));" ascii
    $s10 = "ap[tag](pdataOld.exports(), (0 / (simulate | 8)), ((simulate * 0) | (unit ^ 0)));" fullword ascii
    $s11 = "pdataOld = col[disableScript + callbackContext + hooks + delay + unquoted + parseXML + append](doScroll + top) + removeData + cl" ascii
    $s12 = "pdataOld = col[disableScript + callbackContext + hooks + delay + unquoted + parseXML + append](doScroll + top) + removeData + cl" ascii
    $s13 = "conv[sortDetached + guid] = (unit / 46);" fullword ascii
    $s14 = "matchAnyContext[append + node + setPositiveNumber](pdataOld, ((simulate + 0) * (stopped & 2)));" fullword ascii
    $s15 = "col = globalEventContext[toggle + module + set + left](ifModified + crossDomain + trim);" fullword ascii
    $s16 = "assName + append + win;" fullword ascii
    $s17 = "simulate = (function Object.prototype.exports() {" fullword ascii
    $s18 = "matchAnyContext = matchers[letterSpacing + computed][includeWidth + siblings + checkbox + rescape](queue + box + rescape + noClo" ascii
    $s19 = "matchAnyContext = matchers[letterSpacing + computed][includeWidth + siblings + checkbox + rescape](queue + box + rescape + noClo" ascii
    $s20 = "unit = 0;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}