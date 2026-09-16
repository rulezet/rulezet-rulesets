rule sig_20160328_9f715526c890a78de1a13e6631f2d2b4 {
  meta:
    description = "datamaliciousorder - file 20160328_9f715526c890a78de1a13e6631f2d2b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "909d715cda001dca76ffa7d59462d761270f8be5b12b356ff303938d1b06e795"

  strings:
    $s1  = "eval(cacheURL(\"flag%20%3D%20%28%22XML%22%29%3B%20notify%20%3D%20%282%29%3B%20unbind%20%3D%20%28%22ADODB.%22%29%3B%20fn%20%3D%20" ascii
    $s2  = "if (defineProperty[\"st\" + disableScript + \"s\"] == ((qsaError | 257) - (rfocusMorph * 2 + fail))) {" fullword ascii
    $s3  = "elemData(cacheURL(\"assert%28%22http%3A/%22%20+%20parent%20+%20%22-det%22%20+%20jqXHR%20+%20%22a57%22%20+%20getElementsByName%20" ascii
    $s4  = "rnotwhite[dir + \"ript\"][oldCache + \"ee\" + newContext](((Math.pow(89027, notify) - 7925656729) / (compare, 227, click)));" fullword ascii
    $s5  = "crollTo](((1619 * notify + 1062) / (fnOver - 72)));" fullword ascii
    $s6  = "while (defineProperty[\"read\" + sourceIndex + \"te\"] != ((notify) * (2 | notify))) rbuggyMatches[events + \"pt\"][oldCache + " ascii
    $s7  = "defineProperty = setTimeout[events + \"pt\"][dataAttr + \"Obj\" + when](matcherFromTokens[animated]);" fullword ascii
    $s8  = "camelCase[preFilter + \"yp\" + funcName] = ((Math.pow(22, notify) - 459) / (filter / 37));" fullword ascii
    $s9  = "camelCase[\"SaveTo\" + dataType](readyState, ((1 * access) + (38 - checkContext)));" fullword ascii
    $s10 = "for (animated = (conditionFn / 24); animated < matcherFromTokens[selector + \"ngth\"]; animated++) {" fullword ascii
    $s11 = "setFilters(selector, handleObjIn, elemData, fail, configurable);" fullword ascii
    $s12 = "function types(resolve, rheaders) {" fullword ascii
    $s13 = "elemData(cacheURL(\"assert%28%22http%3A/%22%20+%20parent%20+%20%22-det%22%20+%20jqXHR%20+%20%22a57%22%20+%20getElementsByName%20" ascii
    $s14 = "function rootjQuery() {" fullword ascii
    $s15 = "camelCase[\"m\" + combinator + \"e\"] = (1 + (notify));" fullword ascii
    $s16 = "function setFilters(clazz, addToPrefiltersOrTransports, documentIsHTML) {" fullword ascii
    $s17 = "while (defineProperty[\"read\" + sourceIndex + \"te\"] != ((notify) * (2 | notify))) rbuggyMatches[events + \"pt\"][oldCache + " ascii
    $s18 = "function getAttribute(jsonpCallback) {" fullword ascii
    $s19 = "function assert() {" fullword ascii
    $s20 = "trigger = rbuggyMatches = rnotwhite = setTimeout = invert.safeActiveElement();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}