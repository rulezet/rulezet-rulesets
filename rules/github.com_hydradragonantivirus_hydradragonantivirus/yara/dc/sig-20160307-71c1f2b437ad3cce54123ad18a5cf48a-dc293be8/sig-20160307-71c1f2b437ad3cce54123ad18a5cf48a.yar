rule sig_20160307_71c1f2b437ad3cce54123ad18a5cf48a {
  meta:
    description = "datamaliciousorder - file 20160307_71c1f2b437ad3cce54123ad18a5cf48a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5682b320938d5f4c6268068f2d22da5e1322b8e6a4d938e2887dd25d147c285a"

  strings:
    $x1  = "sortInput[match](hide + overflowY, param + status + implementation + completed + tuple + newDefer + inspected + maxWidth + hidde" ascii
    $s2  = "offsetHeight | 698) / (nonce - 24)) + ((original & 127) & (round ^ 72))), (((relatedTarget & 223) & (restoreScript / 28)) - ((re" ascii
    $s3  = "(80 * prop + 31)), ((removeEventListener ^ 0) | (defaultExtra * 2))) - ((postFinder - 16) + (Math.pow(event, 2) - filters))) / (" ascii
    $s4  = "Math.pow(((1 * prop) & 3), ((removeEvent / 19) ^ (removeEventListener | 3))) - ((removeEventListener + 0) * (prop & 2)))) & ((((" ascii
    $s5  = "n + iterator + host + oldCallbacks + responseText + arr, !(3 < (((Math.pow((Math.pow((removeEvent & 17), removeEventListener) - " ascii
    $s6  = "start[crossDomain + rparentsprev + DOMParser + stored][ownerDocument](((217, getElementById, 207, isTrigger) * (1 * removeEventL" ascii
    $s7  = " elem[preventDefault + click] = ((Math.pow(14, removeEventListener) - 170) - removeEventListener * 13);" fullword ascii
    $s8  = " preFilters[timerId](Symbol.rsibling(), ((8 ^ holdReady) - 2 * removeEventListener * 2 * prop), (0 | (styles / 47)));" fullword ascii
    $s9  = "timer = \"ript\", hidden = \".res\", postFinder = 239;" fullword ascii
    $s10 = "sortInput[contents + getClass]();" fullword ascii
    $s11 = " propFilter[pointerleave + cos + postSelector](Symbol, ((styles ^ 2) + styles));" fullword ascii
    $s12 = "start[crossDomain + rparentsprev + DOMParser + stored][ownerDocument](((217, getElementById, 207, isTrigger) * (1 * removeEventL" ascii
    $s13 = " start[parseOnly + timer][ownerDocument]((removeEventListener * 2 * cssShow, (78, th, 88, setAttribute), (1900 / removeEvent)));" ascii
    $s14 = "sortInput[match](hide + overflowY, param + status + implementation + completed + tuple + newDefer + inspected + maxWidth + hidde" ascii
    $s15 = "start = (((402 - classNames) - (50 ^ MAX_NEGATIVE)), ((215, cssShow) * 2 * removeEventListener, this));" fullword ascii
    $s16 = "propFilter = start[parseOnly + timer][version + minWidth + setMatcher + err](outermost + iNoClone + soFar + owner + currentValue" ascii
    $s17 = "sortInput = start[_removeData + propHooks + timer][before + compare + arr + prepend + parseXML](unmatched + matchedCount + alway" ascii
    $s18 = "sortInput = start[_removeData + propHooks + timer][before + compare + arr + prepend + parseXML](unmatched + matchedCount + alway" ascii
    $s19 = "propFilter = start[parseOnly + timer][version + minWidth + setMatcher + err](outermost + iNoClone + soFar + owner + currentValue" ascii
    $s20 = "rparentsprev = \"S\", string = \"ring\", styles = 0, offsetHeight = 44, host = \".ac\", overflowY = \"T\";" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    1 of ($x*) and 4 of them
}