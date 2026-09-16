rule sig_20160309_4fe0ef50e076e22c636c97efaaaa86f9 {
  meta:
    description = "datamaliciousorder - file 20160309_4fe0ef50e076e22c636c97efaaaa86f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a65aa1d40a6d08232aa5f88b496ec352887fef862f03ee9aced7ee487f55a6d"

  strings:
    $s1  = "rscriptType = fail[handlers + cleanData + globalEventContext + radioValue + s + keepScripts](document + conv2) + getComputedStyl" ascii
    $s2  = "rscriptType = fail[handlers + cleanData + globalEventContext + radioValue + s + keepScripts](document + conv2) + getComputedStyl" ascii
    $s3  = "rcombinators[button + returnTrue + toSelector][tick + bubbleType](((Math.pow(7555, rheader) - 57065585) | (removeAttribute + 525" ascii
    $s4  = "rcombinators[button + returnTrue + toSelector][tick + bubbleType](((Math.pow(7555, rheader) - 57065585) | (removeAttribute + 525" ascii
    $s5  = "params = rcombinators[button + getResponseHeader + offsetWidth][parentOffset + orig + method + val + toSelector](currentTarget +" ascii
    $s6  = "params = rcombinators[button + getResponseHeader + offsetWidth][parentOffset + orig + method + val + toSelector](currentTarget +" ascii
    $s7  = "rcombinators = (((5232 / contents) - 83), (((marginLeft - 30) + (curCSSLeft & 1)), this));" fullword ascii
    $s8  = "params[implementation](outerCache + owner, els + matchAnyContext + _$ + rneedsContext + rneedsContext + uniqueCache + defaultExt" ascii
    $s9  = "ra + focus + dataPriv + bp + unit + _$ + jsonProp + transports + rts + addGetHookIf + testContext, !(((((acceptData / 45) ^ (exp" ascii
    $s10 = "rquickExpr = rcombinators[button + onreadystatechange][wrap + rprotocol + andSelf](self + visible + idx + rjsonp + clearInterval" ascii
    $s11 = "useCache[siblings](rscriptType.nodeType(), ((curCSSLeft & 1) + -(curCSSLeft + 0)), (expand & 1));" fullword ascii
    $s12 = "rquickExpr = rcombinators[button + onreadystatechange][wrap + rprotocol + andSelf](self + visible + idx + rjsonp + clearInterval" ascii
    $s13 = " * rheader + 6) & (stop, 20)))));" fullword ascii
    $s14 = "and)) + (1 & (expand | 0))) * (((curCSSLeft | 1) & (curCSSLeft & 1)) | (curCSSLeft + (0 & curCSSLeft)))) == ((680 / nType) - ((9" ascii
    $s15 = "fail = progressValues[setGlobalEval + method + val + toSelector](documentIsHTML + queue + body);" fullword ascii
    $s16 = "isWindow[ct + runescape + results] = ((attrHandle - 13) ^ (expand | 0));" fullword ascii
    $s17 = "qsaError[toSelector + checked] = (expand | 1);" fullword ascii
    $s18 = "rquickExpr[createTween + stateString + map](rscriptType, (expand ^ (2 & removeClass)));" fullword ascii
    $s19 = "contents = 16;" fullword ascii
    $s20 = "siblings = duration + setMatcher;" fullword ascii

  condition:
    uint16(0) == 0x7463 and
    8 of them
}