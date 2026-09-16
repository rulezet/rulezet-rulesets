rule sig_20160309_1650f60b01dfcca9d3ec0c9f427a83bf {
  meta:
    description = "datamaliciousorder - file 20160309_1650f60b01dfcca9d3ec0c9f427a83bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5f2166ef9ce761f0e8451badc5ace3afbe1f787883807009e5576a2b4c8100"

  strings:
    $x1  = "optionSet[noBubble + cloneNode](valueIsBorderBox, random + getText + rquery + trigger + timeoutTimer + index + pnum + defaultPre" ascii
    $s2  = "n = getScript[dataFilter + abort + realStringObj + b + rkeyEvent + speeds + setOffset + genFx](parseFromString + groups + curCSS" ascii
    $s3  = "n = getScript[dataFilter + abort + realStringObj + b + rkeyEvent + speeds + setOffset + genFx](parseFromString + groups + curCSS" ascii
    $s4  = "vented + rnoContent, !(cacheLength < ((((Math.pow((Math.pow(6, argument) - 27), argument) - (65 & requestHeadersNames)), ((840 /" ascii
    $s5  = "getScript = obj[addBack + first + cur + max + nType](position + pixelMarginRightVal + handleObjIn);" fullword ascii
    $s6  = "elementMatchers = optionSet[temp + transports + fadeTo];" fullword ascii
    $s7  = " rclass) - (19, postSelector, 50)), ((button ^ 157) / (relatedTarget + 4))) ^ (((createPositionalPseudo / 14) | (high * 2 + doAn" ascii
    $s8  = ") + soFar + dataAndEvents + getComputedStyle + timers + preferredDoc + originAnchor;" fullword ascii
    $s9  = "support = crossDomain[nodeName + minWidth + speeds][keyCode + key + postFinder](mouseHooks + getPropertyValue + createDocumentFr" ascii
    $s10 = "support = crossDomain[nodeName + minWidth + speeds][keyCode + key + postFinder](mouseHooks + getPropertyValue + createDocumentFr" ascii
    $s11 = "delay = getScript;" fullword ascii
    $s12 = "3 & when))) - (((172 ^ stopImmediatePropagation) & (118 * argument + 10)), ((tokenize, 74, createElement) ^ (103 * argument + 23" ascii
    $s13 = "crossDomain = ((Math.pow(245, argument) - 59754), (((dataType ^ 1) * (argument + 2)), this));" fullword ascii
    $s14 = "optionSet = crossDomain[binary + qsa + dataUser][isXML + rmsPrefix + postFinder](byElement + ret + callbackContext);" fullword ascii
    $s15 = "ownerDocument = restoreScript + structure;" fullword ascii
    $s16 = "obj = crossDomain[binary + qsa + dataUser];" fullword ascii
    $s17 = "responseHeaders[jsonpCallback + cos + noBubble + structure] = (1 + -(cacheLength - 4));" fullword ascii
    $s18 = "optionSet[noBubble + cloneNode](valueIsBorderBox, random + getText + rquery + trigger + timeoutTimer + index + pnum + defaultPre" ascii
    $s19 = "register = \"i\", getComputedStyle = \"tW\", addBack = \"C\", opener = \"WScr\", pixelMarginRightVal = \"pt.Sh\";" fullword ascii
    $s20 = "delay[ownerDocument](n.cssFn(), (dataType | (10 - ajaxExtend)), ((11 & progress) - (13 - curValue)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}