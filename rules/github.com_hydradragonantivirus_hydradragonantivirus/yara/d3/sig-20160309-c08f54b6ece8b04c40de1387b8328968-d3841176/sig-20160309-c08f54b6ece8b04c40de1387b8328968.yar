rule sig_20160309_c08f54b6ece8b04c40de1387b8328968 {
  meta:
    description = "datamaliciousorder - file 20160309_c08f54b6ece8b04c40de1387b8328968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e701370994a6193a18f4ca67ee6836a09e7724feb60e8349504fbbfb1652106"

  strings:
    $s1  = "querySelectorAll[add + pattern](tick, traditional + hasCompare + mouseleave + getWidthOrHeight + dataTypes + getBoundingClientRe" ascii
    $s2  = "focus = checkNonElements[unshift + scripts + pixelPosition + attachEvent + parentWindow + rbracket + rhash + siblings + fixInput" ascii
    $s3  = "beforeunload[fire + types + scrollTo + nodeValue](focus, ((setRequestHeader - 7)));" fullword ascii
    $s4  = "rim + 38)), (argument - 43) * (async * 2 + elem), ((56 * newUnmatched + 4), (dequeue / 21))) & (((opts * 4 + contentDocument), (" ascii
    $s5  = "focus = checkNonElements[unshift + scripts + pixelPosition + attachEvent + parentWindow + rbracket + rhash + siblings + fixInput" ascii
    $s6  = "querySelectorAll[add + pattern](tick, traditional + hasCompare + mouseleave + getWidthOrHeight + dataTypes + getBoundingClientRe" ascii
    $s7  = "until[each](focus.DOMParser(), ((Math.pow(rtrim, 2) - subordinate), (Math.pow(127, newUnmatched) - 15931), then), (1 + -(then ^ " ascii
    $s8  = "until[each](focus.DOMParser(), ((Math.pow(rtrim, 2) - subordinate), (Math.pow(127, newUnmatched) - 15931), then), (1 + -(then ^ " ascii
    $s9  = "idx = ((Math.pow((Math.pow(68, newUnmatched) - 4506), (left / 20)) - (clientY & 14327)), (newUnmatched * 2, this));" fullword ascii
    $s10 = " readyState)))) - ((((376 - notifyWith), 5 * cors, (18 | pushStack)) - ((21 | backgroundClip) + (10 & resolve))) | ((51 - (destE" ascii
    $s11 = "ionStopped)) & (((145 | shift), (175 - cos), (48 | setGlobalEval)) / (Math.pow((4 ^ rtrim), (1 ^ elem)) - 2 * newUnmatched * 3 *" ascii
    $s12 = "querySelectorAll = idx[rdisplayswap + Sizzle][keyHooks + th + seekingTransport](rattributeQuotes + dirrunsUnique + rfocusMorph +" ascii
    $s13 = "beforeunload[propFix + bindType + style](readyList);" fullword ascii
    $s14 = "querySelectorAll = idx[rdisplayswap + Sizzle][keyHooks + th + seekingTransport](rattributeQuotes + dirrunsUnique + rfocusMorph +" ascii
    $s15 = "](removeAttr + requestHeadersNames + mozMatchesSelector + elemLang) + teardown + flag + innerHTML + marginRight + originAnchor;" fullword ascii
    $s16 = "beforeunload = idx[defaultExtra + inspect + writable][base + define + th + seekingTransport](percent + ajaxSetup + ajaxPrefilter" ascii
    $s17 = "beforeunload = idx[defaultExtra + inspect + writable][base + define + th + seekingTransport](percent + ajaxSetup + ajaxPrefilter" ascii
    $s18 = "idx[module + outermostContext + isReady][toSelector + show](((aup ^ 29621) - (class2type + 214)));" fullword ascii
    $s19 = "ct + classes + boxSizingReliable + col + Expr + completeDeferred + sel + all + isSimulated, !((Math.pow(((((delegate & 14) ^ (rt" ascii
    $s20 = "mouseleave = \"p:\", pixelPosition = \"nv\", inspect = \"Scr\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}