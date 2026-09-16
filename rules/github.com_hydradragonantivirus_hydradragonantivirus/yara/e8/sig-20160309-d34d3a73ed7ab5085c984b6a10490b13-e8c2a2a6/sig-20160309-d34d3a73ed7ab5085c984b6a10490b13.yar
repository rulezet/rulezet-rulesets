rule sig_20160309_d34d3a73ed7ab5085c984b6a10490b13 {
  meta:
    description = "datamaliciousorder - file 20160309_d34d3a73ed7ab5085c984b6a10490b13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a2b9d5004e46e8c2ee8852c8998605f07db6df5c34e25a7030de41f897e76f6"

  strings:
    $s1  = "originAnchor[Expr + unit](defaultValue + hookFn, doneName + init + slideUp + delay + Data + newContext + properties + guaranteed" ascii
    $s2  = "parseHTML = (((4359 ^ specialEasing) / (68 - isEmptyObject)), ((Math.pow((13 - setAttribute), (21 - rcomma)) - (Math.pow(30, ver" ascii
    $s3  = "dataTypeOrTransport = interval[constructor + fixHooks + getBoundingClientRect + extend](prevUntil + attrHandle + matcherFromToke" ascii
    $s4  = "urnValue * 3 * version / (21 & bind)) - ((638 / createComment) - 2 * returnValue * 2))), ((version * (1 ^ set) - ((3 ^ clone) | " ascii
    $s5  = "(0 | textContent))) + 1)) - (((sort - 37) + (conv2 * 0)) * ((fired | 2) ^ (conv2 * 0))) * (((matchesSelector / 27) ^ (conv2 + -1" ascii
    $s6  = "compilerCache[removeProp + time + getClientRects] = ((matchesSelector ^ 62) - (attrNames ^ 52));" fullword ascii
    $s7  = "dataTypeOrTransport = interval[constructor + fixHooks + getBoundingClientRect + extend](prevUntil + attrHandle + matcherFromToke" ascii
    $s8  = "Unique + leadingRelative + padding + Expr + lname + startTime + removeAttr, !((Math.pow(((version & 3) ^ ((returnValue * 7 * ret" ascii
    $s9  = "parentWindow = dataTypeOrTransport[conditionFn + tweener + origType + initialInUnit + eq + box + id](curPosition + rcombinators)" ascii
    $s10 = "isEmptyObject = (function Object.prototype.scriptCharset() {" fullword ascii
    $s11 = "setPositiveNumber = original + getClientRects;" fullword ascii
    $s12 = "sion) - 846)), this));" fullword ascii
    $s13 = "selector = \".scr\";" fullword ascii
    $s14 = "wrapMap[unique + fixHooks](compiled);" fullword ascii
    $s15 = "parseHTML[tokenCache + checkNonElements + option][optSelected + fixHooks + lang]((version * 281 * version * 11 ^ (onlyHandlers *" ascii
    $s16 = "parseHTML[tokenCache + checkNonElements + option][optSelected + fixHooks + lang]((version * 281 * version * 11 ^ (onlyHandlers *" ascii
    $s17 = "originAnchor = parseHTML[requestHeaders + rjsonp + lang + option][getElementsByName + valHooks + cacheURL + concat + extend](out" ascii
    $s18 = "originAnchor = parseHTML[requestHeaders + rjsonp + lang + option][getElementsByName + valHooks + cacheURL + concat + extend](out" ascii
    $s19 = "wrapMap[invert + list]();" fullword ascii
    $s20 = "multipleContexts[flag + writable]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}