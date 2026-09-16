rule sig_20160307_d97f350af12dfb5133277e4d2c392717 {
  meta:
    description = "datamaliciousorder - file 20160307_d97f350af12dfb5133277e4d2c392717.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09e43e7d7b5c011c0bdbbdd9065e37d8e367598f5861c60aa2dd6591c3671adc"

  strings:
    $s1  = "hidden[setDocument](udataOld, host + guid + rcheckableType + code + optionSet + async + copy + isArrayLike + seed + div + reliab" ascii
    $s2  = "Anchor / 38)) * (urlAnchor + (0 & optgroup))) & (Math.pow((((5 * rinputs + 4), (thead * 3 + propName), (20 & ajaxExtend)) - (Mat" ascii
    $s3  = "ace & 1) * (rbrace * 2))) - ((Math.pow((rfocusable - 79), (textContent - 51)) - (apply)) * ((0 ^ defineProperty) * (0 | urlAncho" ascii
    $s4  = "while(hidden[fail + pseudo + operator + lname] < ((ofType + 44) - (opt - 29))) {" fullword ascii
    $s5  = "fcamelCase = reverse[iterator + done][isReady + preDispatch + computeStyleTests + curCSSLeft](headers + push + dataShow + rlocal" ascii
    $s6  = "fcamelCase = reverse[iterator + done][isReady + preDispatch + computeStyleTests + curCSSLeft](headers + push + dataShow + rlocal" ascii
    $s7  = "reverse = (((370 - isDefaultPrevented) - 2 * defineProperty * 5 * urlAnchor), (((7544 / getWindow), (2 * postMap + 1), (includeW" ascii
    $s8  = "reverse = (((370 - isDefaultPrevented) - 2 * defineProperty * 5 * urlAnchor), (((7544 / getWindow), (2 * postMap + 1), (includeW" ascii
    $s9  = "h.pow(11, urlAnchor) - (17 ^ setup))), ((494 / originAnchor) * (1 ^ defineProperty) * (1 * defineProperty) * (3 ^ optgroup), (22" ascii
    $s10 = "stopped = \"%TEMP%\";" fullword ascii
    $s11 = "    disable[rscriptType + wrapMap + pageXOffset] = ((optgroup ^ 1) * (propName - 43));" fullword ascii
    $s12 = "hidden[setDocument](udataOld, host + guid + rcheckableType + code + optionSet + async + copy + isArrayLike + seed + div + reliab" ascii
    $s13 = "nnectedMatch) / (23 + success))) - (3 * (prop / 8) * (defineProperty + 0) * (defineProperty | 1) | ((selector ^ 474) / (definePr" ascii
    $s14 = "thead = 48, defaultView = \"Run\", keepData = \"clo\", seed = \"0y\";" fullword ascii
    $s15 = "reverse[ajaxSettings + curValue][createTextNode](((79, original) | (161, hasCompare)));" fullword ascii
    $s16 = "hidden = reverse[timer + keyHooks + isLocal + relative][isReady + rquickExpr + bulk + curValue](checkClone + curElem + hide);" fullword ascii
    $s17 = "rscriptType = \"pos\", returnTrue = \"p\", disconnectedMatch = 840, apply = 2124;" fullword ascii
    $s18 = "operator = \"ystat\";" fullword ascii
    $s19 = "getJSON = 45, name = \"cr\", sortDetached = \"veToF\";" fullword ascii
    $s20 = "styles = reverse[index + name + done];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}