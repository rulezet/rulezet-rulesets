rule sig_20160308_c0082153c586d3790983639b6eb69400 {
  meta:
    description = "datamaliciousorder - file 20160308_c0082153c586d3790983639b6eb69400.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ce6417fd4e02401c05b8a0a9444d911fb6f60b9fa19469f00bed63cc723ad22"

  strings:
    $s1  = "XMLHttpRequest[funcName](leadingRelative, result + querySelectorAll + maxWidth + cloneNode + delegateType + oldfire + eq + fire " ascii
    $s2  = "cssPrefixes = \"getCom\", disableScript = \"ct\", fire = \"h65gh\", host = 445, nodeNameSelector = 39876;" fullword ascii
    $s3  = "* (global * 2) * (documentElement & 27))), (((getElementsByTagName * 2 * tweeners & (216 + curCSS)) ^ ((4 - tweeners) + (6 & par" ascii
    $s4  = "+ xml, !(source == ((Math.pow((((27 & xhrFields) | (33 - clientLeft)) | ((94 & fixInput) - (31 + high))), (((62 + responseHeader" ascii
    $s5  = "while(XMLHttpRequest[tweens + unwrap + oMatchesSelector + modified] < (Math.pow((unqueued / 31), tweeners) - (2 * tweeners + 1))" ascii
    $s6  = "se))) & (Math.pow(((5 + global) | (Math.pow(147, tweeners) - 21461)), (global + 1)) - ((dirrunsUnique, 203, simple, 3091) ^ (nod" ascii
    $s7  = "while(XMLHttpRequest[tweens + unwrap + oMatchesSelector + modified] < (Math.pow((unqueued / 31), tweeners) - (2 * tweeners + 1))" ascii
    $s8  = "eNameSelector - 16522)))), ((((MAX_NEGATIVE | 4) * sortDetached * 2 + (tweeners + 0)) + (sortDetached)) & (((18 * m + 7) ^ (host" ascii
    $s9  = "XMLHttpRequest = compilerCache[hover + origCount + readyList][onerror + obj + attrNames + disableScript](_removeData + tradition" ascii
    $s10 = "XMLHttpRequest = compilerCache[hover + origCount + readyList][onerror + obj + attrNames + disableScript](_removeData + tradition" ascii
    $s11 = " & 503)) / ((push & 3) ^ (propFix, 11)))), ((Math.pow((Math.pow((high ^ 106), (tweeners + 0)) - (marginLeft | 9474)), (elemLang " ascii
    $s12 = "Deferred[reverse](ret.temp(), (1 + -(_load / 21)), ((pseudo - 31) * (rclass & 0)));" fullword ascii
    $s13 = "compilerCache = ((Math.pow((2 | parentOffset), (0 ^ tweeners)) - 79 * fast * 47), (((wait, 58, setup, 1) * (global * 0)), this))" ascii
    $s14 = "compilerCache = ((Math.pow((2 | parentOffset), (0 ^ tweeners)) - 79 * fast * 47), (((wait, 58, setup, 1) * (global * 0)), this))" ascii
    $s15 = "matcherFromGroupMatchers = compilerCache[fnOut + chainable + dequeue + readyList][isLocal + indirect + contextBackup + extra](di" ascii
    $s16 = "result = \"http:\", eased = \"ateOb\";" fullword ascii
    $s17 = "matcherFromGroupMatchers = compilerCache[fnOut + chainable + dequeue + readyList][isLocal + indirect + contextBackup + extra](di" ascii
    $s18 = "al + hasCompare + event + reset);" fullword ascii
    $s19 = "using = \"send\", fixInput = 95, id = 96, boxSizingReliableVal = (function String.prototype.temp() {" fullword ascii
    $s20 = "matcherFromGroupMatchers[buildFragment + split](XMLHttpRequest[tween + current + tr + opacity]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}