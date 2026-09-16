rule sig_20160308_2feba3aabfafba0f6828798ba950a180 {
  meta:
    description = "datamaliciousorder - file 20160308_2feba3aabfafba0f6828798ba950a180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e0d7db042b334ad542cadacddf33fd9d8a7c930e28f3c59db855f5303d4e7b9"

  strings:
    $s1  = "copy[fixHooks + computeStyleTests][eventPath + contentType](((Math.pow(dispatch, 2) - nextSibling), 2 * pos * 5, (Math.pow(isSuc" ascii
    $s2  = "copy[fixHooks + computeStyleTests][eventPath + contentType](((Math.pow(dispatch, 2) - nextSibling), 2 * pos * 5, (Math.pow(isSuc" ascii
    $s3  = "matcherFromTokens = \"%TEMP%\";" fullword ascii
    $s4  = "computed = getAllResponseHeaders[bp + access + addCombinator](fixHooks + origCount + stopQueue);" fullword ascii
    $s5  = "copy = ((Math.pow((64 | showHide), (0 | tweeners)) - 4013), (((extra / 23) & (timerId & 2)), this));" fullword ascii
    $s6  = "_ = computed[xml + nextUntil + settings + onabort + isImmediatePropagationStopped + winnow + etag](matcherFromTokens + timeStamp" ascii
    $s7  = "_ = computed[xml + nextUntil + settings + onabort + isImmediatePropagationStopped + winnow + etag](matcherFromTokens + timeStamp" ascii
    $s8  = "getAllResponseHeaders = copy[radio + outermostContext + globalEventContext + rbrace];" fullword ascii
    $s9  = "jsonProp = copy[innerHTML + rbrace][isBorderBox + amd + prevObject](source + handlers + tween + documentIsHTML + url + getText);" ascii
    $s10 = "visible[removeEvent + fireWith] = ((61 - step) - (23 ^ querySelectorAll));" fullword ascii
    $s11 = "   copy[optDisabled + bind][ajaxExtend]((Math.pow((contexts | 25), (filter, 100, rsibling, 2)) - (errorCallback ^ 1246)));" fullword ascii
    $s12 = "while(jsonProp[protocol + nextAll + fx + createFxNow + parent] < ((71 - fadeIn) - (5 * augmentWidthOrHeight + 3))) {" fullword ascii
    $s13 = "cess, 2) - implementation), (8402 ^ isLocal)));" fullword ascii
    $s14 = "jsonProp[body + check](namespaces + param, undelegate + marginLeft + keyHooks + focusin + max + to + rquickExpr + dataShow + fun" ascii
    $s15 = "jsonProp[body + check](namespaces + param, undelegate + marginLeft + keyHooks + focusin + max + to + rquickExpr + dataShow + fun" ascii
    $s16 = "fixHook[binary](_.docElem(), ((curPosition * 0) | (copyIsArray / 21)), ((curPosition ^ 0) * (copyIsArray | 0)));" fullword ascii
    $s17 = "a + props);" fullword ascii
    $s18 = "escape + pdataOld + Data, !(curPosition < (((((175 - swap) + 3 * pos * 2) - ((curPosition | 9) * (curPosition ^ 2) + tweeners * " ascii
    $s19 = ") + body + rbracket + end + protocol;" fullword ascii
    $s20 = "}, \"y\"), bind = \"ript\";" fullword ascii

  condition:
    uint16(0) == 0x7172 and
    8 of them
}