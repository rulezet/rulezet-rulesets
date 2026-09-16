rule sig_20160308_b8ecc90a61df5654d7de59cb837c9077 {
  meta:
    description = "datamaliciousorder - file 20160308_b8ecc90a61df5654d7de59cb837c9077.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9223fa6e8a2824f9f0c0447de7ae83923531aa376efab206ba1ab1668f841dfa"

  strings:
    $s1  = "parentOffset[dest + nodeType + define](parent + fast, rtrim + bind + getPropertyValue + camel + cssProps + isFunction + tmp + th" ascii
    $s2  = "isTrigger[iframe + clientX][rmouseEvent + removeData + computeStyleTests](((231 - processData) & (158, finish, 102)));" fullword ascii
    $s3  = "pointerenter[computeStyleTests + what + docElem + blur + define] = (keepScripts + -1);" fullword ascii
    $s4  = "while(parentOffset[createOptions + always + finalDataType + slideUp] < ((2 + keepScripts) + (9 / operator))) {" fullword ascii
    $s5  = "getWidthOrHeight = params[msg + outermost + matched + makeArray](tfoot + prevAll + hasCompare + curTop);" fullword ascii
    $s6  = "preFilter = getWidthOrHeight[box + dataAttr + Sizzle + returnTrue + jsonp + filter + defaultPrefilter + special](soFar + newCach" ascii
    $s7  = "isTrigger = (((80 | includeWidth) + (Math.pow(44, fixHooks) - 1861)), ((m - 29), this));" fullword ascii
    $s8  = "merge = isTrigger[load + prop + matcherOut][msg + isNumeric + setPositiveNumber + contentDocument](radioValue + speed + superMat" ascii
    $s9  = "merge = isTrigger[load + prop + matcherOut][msg + isNumeric + setPositiveNumber + contentDocument](radioValue + speed + superMat" ascii
    $s10 = "iframe = \"WScrip\", dest = \"op\", script = 7, pageYOffset = 13, eventDoc = \"teO\";" fullword ascii
    $s11 = "parentOffset[dest + nodeType + define](parent + fast, rtrim + bind + getPropertyValue + camel + cssProps + isFunction + tmp + th" ascii
    $s12 = "temp = 4088;" fullword ascii
    $s13 = "ntX](jQuery + proxy + traditional + timeoutTimer);" fullword ascii
    $s14 = "piled)) | ((212, stopOnFalse, 191, temp) / (8 ^ ajaxConvert))), (((0 ^ beforeunload) | (5 | includeWidth)) ^ ((15 & isBorderBox)" ascii
    $s15 = "e + uniqueCache) + ajaxPrefilter + scriptCharset + responseType + invert;" fullword ascii
    $s16 = "parentOffset = isTrigger[bubbleType + createCache][msg + outermost + eventDoc + readyWait + isImmediatePropagationStopped + clie" ascii
    $s17 = " / (5 & script)))))));" fullword ascii
    $s18 = "getPropertyValue = \"okoko\", nodeType = \"e\", attachEvent = (function Object.prototype.rtagName() {" fullword ascii
    $s19 = "operator = 9;" fullword ascii
    $s20 = "preFilter = getWidthOrHeight[box + dataAttr + Sizzle + returnTrue + jsonp + filter + defaultPrefilter + special](soFar + newCach" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}