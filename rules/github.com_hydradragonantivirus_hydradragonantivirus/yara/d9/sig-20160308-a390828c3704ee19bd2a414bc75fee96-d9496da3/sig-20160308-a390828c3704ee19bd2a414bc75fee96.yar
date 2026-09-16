rule sig_20160308_a390828c3704ee19bd2a414bc75fee96 {
  meta:
    description = "datamaliciousorder - file 20160308_a390828c3704ee19bd2a414bc75fee96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb09b8799939d136734e394aff4af5eb9ff0f03ed682f9293148de03e6eb4a7b"

  strings:
    $s1  = "rtypenamespace[easing](pageX, udataOld + conv2 + timeStamp + second + overflow + ap + closest + rnamespace + setMatched + initia" ascii
    $s2  = "dispatch = orig[nodeType + elementMatcher + risSimple + nextSibling + shift + visibility + keyCode + init](addEventListener + ne" ascii
    $s3  = "pixelMarginRightVal = (((434 & els) - (73 * isFunction + 31)), (((compile, 4, cssHooks, 135), (postSelector ^ 196), (compile * 5" ascii
    $s4  = "pixelMarginRightVal = (((434 & els) - (73 * isFunction + 31)), (((compile, 4, cssHooks, 135), (postSelector ^ 196), (compile * 5" ascii
    $s5  = "pixelMarginRightVal[remaining + expando][getAllResponseHeaders + bindType + valHooks](((first - 16013) / (isFunction | 9)));" fullword ascii
    $s6  = "unit[position + getWidthOrHeight + stopOnFalse](dispatch, (16 - amd));" fullword ascii
    $s7  = "while(rtypenamespace[keyHooks + optionSet + rscriptTypeMasked] < ((wrapMap, 155, preFilters) / (20, match, 44))) {" fullword ascii
    $s8  = "unit = pixelMarginRightVal[matched + parseJSON][hide + keyHooks + timerId + toggle + parseJSON](ready + find + matches + err + _" ascii
    $s9  = "unit = pixelMarginRightVal[matched + parseJSON][hide + keyHooks + timerId + toggle + parseJSON](ready + find + matches + err + _" ascii
    $s10 = "response[contexts + value] = keepScripts;" fullword ascii
    $s11 = "has[input](dispatch.selection(), ((0 / th) ^ (0 | keepScripts)), ((0 / compiled) ^ (0 | keepScripts)));" fullword ascii
    $s12 = "l + styles + responseText, !(((((49 - close) | (372 / cssText)) * ((45 - close) ^ 11 * isFunction)), ((8 + originAnchor) * (Math" ascii
    $s13 = "dispatch = orig[nodeType + elementMatcher + risSimple + nextSibling + shift + visibility + keyCode + init](addEventListener + ne" ascii
    $s14 = "orig = focus[hide + winnow + parseHTML + container](marginDiv + structure + clearInterval + bindType + rfocusMorph);" fullword ascii
    $s15 = " + values), (11 ^ fadeOut)), this));" fullword ascii
    $s16 = "input = isTrigger + rbracket;" fullword ascii
    $s17 = "rtypenamespace[easing](pageX, udataOld + conv2 + timeStamp + second + overflow + ap + closest + rnamespace + setMatched + initia" ascii
    $s18 = "focus = pixelMarginRightVal[hasOwn + prevObject + parseJSON];" fullword ascii
    $s19 = "rtypenamespace = pixelMarginRightVal[fail + hasClass + unmatched + safeActiveElement][attrHandle + stopQueue + toggle + parseJSO" ascii
    $s20 = "rtypenamespace = pixelMarginRightVal[fail + hasClass + unmatched + safeActiveElement][attrHandle + stopQueue + toggle + parseJSO" ascii

  condition:
    uint16(0) == 0x736a and
    8 of them
}