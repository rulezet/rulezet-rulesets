rule sig_20160309_60414a182eb8283cc25f893323c9b386 {
  meta:
    description = "datamaliciousorder - file 20160309_60414a182eb8283cc25f893323c9b386.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfad1c9c63806507238b0b3e17a9e9946792ac597efd8c0063a6058944d3c47e"

  strings:
    $s1  = "Expr[rheaders + nodeName + structure] = ((40 | rcomma) - (10 * test));" fullword ascii
    $s2  = "resolveValues[funcName](tweener, needsContext + _removeData + pageYOffset + tokenCache + matchExpr + self + finalDataType + marg" ascii
    $s3  = "delegateTarget[createCache + memory + setMatcher + innerHTML](rcombinators, ((1 * checkDisplay) | 2));" fullword ascii
    $s4  = "delegateTarget[keyHooks](assert);" fullword ascii
    $s5  = "inspected[speeds](rcombinators.sourceIndex(), ((suffix | 0) | suffix), ((32 / includeWidth) * (10 - n)));" fullword ascii
    $s6  = "fadeIn = \"%TEMP%\", parse = 15294, rcomma = 8, namespaces = (function Object.prototype.sourceIndex() {" fullword ascii
    $s7  = "delegateTarget = reliableMarginLeft[responseContainer + nType + funescape][qsa + _ + funescape](addGetHookIf + fx + createPositi" ascii
    $s8  = "ix) * (2 ^ styles)) * (3 & (opener / 44)) / (((strAbort - 29) + (checkDisplay | 142)), (refElements * (2 + styles) + (1 | test))" ascii
    $s9  = "radioValue[values + innerHTML] = (checkDisplay * 2 * _load - (1 | constructor));" fullword ascii
    $s10 = "0) ^ (styles + 2)) + ((styles + -1) / checkDisplay * 2 * _load))) - ((163, active, 165, _queueHooks) + ((2 + suffix) | (71 & par" ascii
    $s11 = "rcombinators = rmargin[flatOptions + childNodes + Sizzle + wait + structure + isArray + isXMLDoc](fadeIn + minWidth) + hasOwnPro" ascii
    $s12 = "am)))) & ((Math.pow((65 - toggleClass), 2) - (checked / 50)) * ((attributes, 7) & (Math.pow(ajaxExtend, 2) - test)) * ((1 + suff" ascii
    $s13 = "raw[proxy + nextAll]();" fullword ascii
    $s14 = "resolveValues = reliableMarginLeft[responseContainer + expanded + input + hasData][keepScripts + sel + expando](addClass + setAt" ascii
    $s15 = "test = 4, setMatcher = \"il\", keepScripts = \"Crea\", fn = \"p\", tuple = \"tr\";" fullword ascii
    $s16 = "resolveValues = reliableMarginLeft[responseContainer + expanded + input + hasData][keepScripts + sel + expando](addClass + setAt" ascii
    $s17 = "onalPseudo + tuple + string);" fullword ascii
    $s18 = "reliableMarginLeft = (((46 & pos) + (2231 / slideToggle)), ((0 & styles), this));" fullword ascii
    $s19 = "fast = reliableMarginLeft[defaultView + namespaces];" fullword ascii
    $s20 = "tribute + rrun + obj + escapedWhitespace);" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}