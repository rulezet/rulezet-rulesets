rule sig_20160308_dffbc55439882a7c73dc49bb8da9a7ba {
  meta:
    description = "datamaliciousorder - file 20160308_dffbc55439882a7c73dc49bb8da9a7ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c89885a4d3a55ab4357f2b170c111113ab2db102c9d3d4e1a8a85fb1210e3cb"

  strings:
    $s1  = "responseFields[propFilter + completeDeferred](startLength + rbracket, step + rheader + rfxtypes + checkNonElements + backgroundC" ascii
    $s2  = "inary) * (194, dataTypes, 2) * (disable, 22, delegateTarget, 2)) / (((Math.pow(easing, 2) - originalSettings) / (7 ^ locked)), (" ascii
    $s3  = "grep[rscriptType](div1.interval(), ((binary | 5) - (Math.pow(ajaxExtend, 2) - opacity)), ((49 - div) - 5 * attrs));" fullword ascii
    $s4  = "(104, abort) / (Math.pow(22, globalEval) - 455)), ((end ^ 2) * (dirruns - 4) + (postDispatch, 6)))))));" fullword ascii
    $s5  = "binary + 5) & (binary | 3) * (accepts / 11)), (((Math.pow(find, 2) - setter) / 37) - ((binary * 1) * (getWidthOrHeight ^ 18)))) " ascii
    $s6  = "2 - (locked + 22)))) + ((((rparentsprev & 366) - (compareDocumentPosition | 149)), (visibility / 46) * (getWidthOrHeight * 2 + b" ascii
    $s7  = "matchIndexes[prop + noBubble][els + param]((getWidthOrHeight * 2 * globalEval * 2 * what * 2 - (Math.pow(pop, 2) - active)));" fullword ascii
    $s8  = "matchIndexes[prop + noBubble][setMatcher + extend]((2 * globalEval + 1) * (computed | 2) * getWidthOrHeight * (2 + getWidthOrHei" ascii
    $s9  = "- ((Math.pow((Math.pow(accepts, 2) - ownerDocument), (1 + binary)) - (370 * ajaxExtend + 64)) - (globalEval * 11 * globalEval * " ascii
    $s10 = "matchIndexes = ((Math.pow((22 + computed), (2 + computed)) - 3 * attr), (((48 - string) + (2 ^ end)), this));" fullword ascii
    $s11 = "div1 = opener[eq + diff + bool + seekingTransport + resolve + checkNonElements + get + fadeTo + dispatch](subtract + index) + no" ascii
    $s12 = "responseFields[propFilter + completeDeferred](startLength + rbracket, step + rheader + rfxtypes + checkNonElements + backgroundC" ascii
    $s13 = "matchIndexes[prop + noBubble][setMatcher + extend]((2 * globalEval + 1) * (computed | 2) * getWidthOrHeight * (2 + getWidthOrHei" ascii
    $s14 = "div1 = opener[eq + diff + bool + seekingTransport + resolve + checkNonElements + get + fadeTo + dispatch](subtract + index) + no" ascii
    $s15 = "processData = \"ToFil\", first = \"ri\";" fullword ascii
    $s16 = "responseFields = matchIndexes[resolveValues + async + noBubble][compiled + tag + ifModified + marginRight + checkNonElements + r" ascii
    $s17 = "ght) * (19 - errorCallback) * (1 * what) * 2 * (m, 171, what));" fullword ascii
    $s18 = "hasOwn[combinator](responseFields[col + converters + undelegate + one]);" fullword ascii
    $s19 = "adown[colgroup + cssShow + completeDeferred] = ((computed & 1) / (what + 20));" fullword ascii
    $s20 = "ootjQuery](returnFalse + scale + scriptCharset + prefilterOrFactory);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}