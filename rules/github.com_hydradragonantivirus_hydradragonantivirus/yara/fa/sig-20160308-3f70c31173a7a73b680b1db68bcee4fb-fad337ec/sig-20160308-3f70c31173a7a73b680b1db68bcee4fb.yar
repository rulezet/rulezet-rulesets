rule sig_20160308_3f70c31173a7a73b680b1db68bcee4fb {
  meta:
    description = "datamaliciousorder - file 20160308_3f70c31173a7a73b680b1db68bcee4fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cce1e74d28cdce2e6efa4de45d77dd066830c76fd0c970b9ead106948048e943"

  strings:
    $s1  = "rclickable = (((1134 / password) * (111, dirrunsUnique, 141, globalEval) + 2), ((Math.pow((b ^ 3), (genFx * 2)) - (when ^ 16)), " ascii
    $s2  = "bubbleType = content[setMatcher + overrideMimeType + _queueHooks + send + ajaxHandleResponses + optionSet + elementMatchers](nid" ascii
    $s3  = "rclickable = (((1134 / password) * (111, dirrunsUnique, 141, globalEval) + 2), ((Math.pow((b ^ 3), (genFx * 2)) - (when ^ 16)), " ascii
    $s4  = "DOMParser[apply + dataAndEvents](done + maxIterations, win + abort + operator + dataTypeOrTransport + which + ajaxTransport + fi" ascii
    $s5  = "bubbleType = content[setMatcher + overrideMimeType + _queueHooks + send + ajaxHandleResponses + optionSet + elementMatchers](nid" ascii
    $s6  = "ath.pow(16, globalEval) - 231)) & ((offsetHeight | 7) * (globalEval | 1) + (parentsUntil / 19)))), (((wrap - 19)) + (((tweeners " ascii
    $s7  = " + postFinder + current) + addToPrefiltersOrTransports + qsa + sibling + isDefaultPrevented + padding + subtract;" fullword ascii
    $s8  = "DOMParser[apply + dataAndEvents](done + maxIterations, win + abort + operator + dataTypeOrTransport + which + ajaxTransport + fi" ascii
    $s9  = ")) - (show - 5388) * (globalEval | 0) * (globalEval & 3))) / ((((Math.pow(rmargin, 2) - sourceIndex) | (164 & reject)) | ((429 +" ascii
    $s10 = "^ 31) * (genFx * 2) + (rmargin / 4)) - ((globalEval ^ 119), (delegateType / 37), (left / 29), (Math.pow(parentsUntil, 2) - stopI" ascii
    $s11 = "while(DOMParser[prev + code + rnoInnerhtml] < (Math.pow((adown, 84, tweeners), (0 ^ globalEval)) - 5)) {" fullword ascii
    $s12 = "sHooks)) + (6 + prop) * (2 & tweeners)) * (0 ^ (genFx * 3)), ((Math.pow(((linear & 183), (Math.pow(webkitMatchesSelector, 2) - n" ascii
    $s13 = "mmediatePropagation))))) == (((((138 + rreturn) | (287 & indirect)) + ((Math.pow(137, globalEval) - 18584) - (duration * 3 + gen" ascii
    $s14 = "Fx))) & (Math.pow(((4400 / structure) * (0 ^ globalEval) + (Math.pow(64, globalEval) - 4027)), ((offsetHeight ^ 0) | (genFx * 2)" ascii
    $s15 = "content = nodeValue[fail + pageY + callbackInverse](related + matchIndexes + window + type);" fullword ascii
    $s16 = "curCSSLeft[opts + hold + easing + collection] = ((noBubble - 152), (offsetHeight & 1));" fullword ascii
    $s17 = "password = 42, isDefaultPrevented = \".\";" fullword ascii
    $s18 = "reliableMarginLeft = rclickable[addGetHookIf + which][div + old + rclass](jQuery + setFilters + firstChild + exports);" fullword ascii
    $s19 = "ewSelector), (175, rtrim), 2 * stopQueue * 3 * globalEval), ((8 + genFx) - (60 - sort))) - (2153 + (stopPropagation * 4 + url)))" ascii
    $s20 = "dirrunsUnique = 188, send = \"nvir\", elementMatchers = \"gs\", boxSizingReliableVal = \"oj6hg\", addToPrefiltersOrTransports = " ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}