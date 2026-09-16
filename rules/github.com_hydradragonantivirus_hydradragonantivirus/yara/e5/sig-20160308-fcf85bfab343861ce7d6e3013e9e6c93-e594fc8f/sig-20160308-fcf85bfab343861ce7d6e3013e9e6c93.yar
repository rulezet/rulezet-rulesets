rule sig_20160308_fcf85bfab343861ce7d6e3013e9e6c93 {
  meta:
    description = "datamaliciousorder - file 20160308_fcf85bfab343861ce7d6e3013e9e6c93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51eb5464efb11db665d6da859b9d61b9f252d5d4f8404607bfd68cb7b81b2f8d"

  strings:
    $s1  = "checkDisplay[callbackName + createCache](postMap, next + elemdisplay + uniqueCache + noCloneChecked + load + prepend + dataFilte" ascii
    $s2  = "visible[exports + results + truncate][scrollTo + rkeyEvent](((contexts ^ 383) * (rcomma - 71) + (defaultExtra * 7)));" fullword ascii
    $s3  = "mozMatchesSelector[targets + augmentWidthOrHeight](checkDisplay[inspectPrefiltersOrTransports + preexisting + push]);" fullword ascii
    $s4  = "r + prevUntil + nidselect + ajaxPrefilter + position + bySet + rhash + pageYOffset + scriptCharset, !(((((Math.pow(buildParams *" ascii
    $s5  = "finish[b](originalSettings.prefilterOrFactory(), ((38 - getAllResponseHeaders)), ((1 ^ i) + -(47 - curLeft)));" fullword ascii
    $s6  = "visible = (((49 ^ show) - (129 - bool)), ((Math.pow((1 * clientLeft), 2) - (i ^ 4)), this));" fullword ascii
    $s7  = "visible[jsonp + file][funcName](((inspected / 36) + (rheader + 16)));" fullword ascii
    $s8  = "mozMatchesSelector[animated + postSelector]();" fullword ascii
    $s9  = "while(checkDisplay[onload + ontype + prepend + len] < ((i | 1) + (prefix - 11))) {" fullword ascii
    $s10 = ") - (fireWith * 2 + global)) * ((23 - insertAfter)) + ((14 * clientLeft + 2) / (pageXOffset * 3 + slideToggle))))) == 5));" fullword ascii
    $s11 = "checkDisplay = visible[exports + handlers][dataAttr + prepend + prependTo + protocol + prepend](removeData + createButtonPseudo " ascii
    $s12 = "checkDisplay = visible[exports + handlers][dataAttr + prepend + prependTo + protocol + prepend](removeData + createButtonPseudo " ascii
    $s13 = " 2 * obj, (1 * buildParams)) - (1147 - add)) / (Math.pow((17 ^ specified), 2) - (isNumeric - 36))) * ((Math.pow((caption + 2), b" ascii
    $s14 = "stateString = cur[cache + setGlobalEval + tokenCache + pixelMarginRightVal + prepend](fail + curCSSTop + childNodes);" fullword ascii
    $s15 = "prepend = \"t\", next = \"http\", binary = 113, tuples = \"se\", ajaxPrefilter = \"sti\";" fullword ascii
    $s16 = "originalSettings = stateString[fcamelCase + aup + animation + cacheURL + isWindow + nodes + isWindow + parts](getter + prev) + s" ascii
    $s17 = "originalSettings = stateString[fcamelCase + aup + animation + cacheURL + isWindow + nodes + isWindow + parts](getter + prev) + s" ascii
    $s18 = "getter = \"%TE\";" fullword ascii
    $s19 = "checkDisplay[callbackName + createCache](postMap, next + elemdisplay + uniqueCache + noCloneChecked + load + prepend + dataFilte" ascii
    $s20 = "animated = \"c\", offsetHeight = \"File\", pageYOffset = \"0k7j6\", fail = \"WSc\", cacheURL = \"nme\", getAllResponseHeaders = " ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}