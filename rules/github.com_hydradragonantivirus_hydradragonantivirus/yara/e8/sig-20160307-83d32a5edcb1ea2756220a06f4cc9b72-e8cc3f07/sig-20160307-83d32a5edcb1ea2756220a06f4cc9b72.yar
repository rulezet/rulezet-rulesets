rule sig_20160307_83d32a5edcb1ea2756220a06f4cc9b72 {
  meta:
    description = "datamaliciousorder - file 20160307_83d32a5edcb1ea2756220a06f4cc9b72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d025e794d54d81b2a37bbb9c83196e8ce5af0ae6ae42f693b58c685f24b9a1e7"

  strings:
    $s1  = "riv * 3) ^ (rneedsContext / 48)) ^ (hide / 10)), (((Math.pow(submit, 2) - compiled) / (47 & parseHTML)) | (2 - setRequestHeader)" ascii
    $s2  = "camelCase[ret + on](isFunction, els + elem + rwhitespace + cacheURL + ret + maxWidth + appendChild + split + val + notifyWith + " ascii
    $s3  = "always[parseJSON + eased][prop + processData + fail](((ajaxConvert & 7799) ^ (pattern & 14079)));" fullword ascii
    $s4  = "always[dataTypes + readyWait + eased][prop + matchedCount]((2 * nativeStatusText * 2 * nativeStatusText * 3 * nativeStatusText |" ascii
    $s5  = "inspectPrefiltersOrTransports + allTypes + xml + flag + bind, !(((((Math.pow((_$ / 13), nativeStatusText) - (381 - delegateCount" ascii
    $s6  = "markFunction[hasContent](prototype.pixelMarginRight(), (parent, (8651 / msMatchesSelector), (24 ^ rinputs), (1 + -dataPriv)), ((" ascii
    $s7  = "currentTarget = 7, compiled = 64140, pattern = 9215, documentElement = 17, factory = \"onme\";" fullword ascii
    $s8  = "markFunction[hasContent](prototype.pixelMarginRight(), (parent, (8651 / msMatchesSelector), (24 ^ rinputs), (1 + -dataPriv)), ((" ascii
    $s9  = "letterSpacing[boxSizingReliable + exports + parseOnly](prototype, ((1 * setRequestHeader) ^ 2));" fullword ascii
    $s10 = "prototype = fast[reject + dataType + factory + dir + orig + getComputedStyle](fadeOut + mouseleave) + safeActiveElement + setup " ascii
    $s11 = "prototype = fast[reject + dataType + factory + dir + orig + getComputedStyle](fadeOut + mouseleave) + safeActiveElement + setup " ascii
    $s12 = "always = (((93 & count) ^ (96 - mapped)), ((Math.pow((19 & match), (1 * nativeStatusText)) - (Math.pow(269, nativeStatusText) - " ascii
    $s13 = "always = (((93 & count) ^ (96 - mapped)), ((Math.pow((19 & match), (1 * nativeStatusText)) - (Math.pow(269, nativeStatusText) - " ascii
    $s14 = "letterSpacing[rclickable](camelCase[temp + inspected + isWindow]);" fullword ascii
    $s15 = "always[dataTypes + readyWait + eased][prop + matchedCount]((2 * nativeStatusText * 2 * nativeStatusText * 3 * nativeStatusText |" ascii
    $s16 = "+ tmp + v + module;" fullword ascii
    $s17 = "prop = \"S\", inspected = \"seBod\", temp = \"Respon\", col = 4;" fullword ascii
    $s18 = " * 2 * (nativeStatusText | 0)))) == load));" fullword ascii
    $s19 = "responseType[returned + conditionFn] = ((dataPriv) + (0 / delegate));" fullword ascii
    $s20 = "letterSpacing = always[fns + attrHandle][adjusted + second + pointerleave + hold](elemData + originalProperties + text);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}