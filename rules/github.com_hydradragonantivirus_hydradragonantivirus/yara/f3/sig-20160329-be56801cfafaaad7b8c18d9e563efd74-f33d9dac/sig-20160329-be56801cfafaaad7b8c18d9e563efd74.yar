rule sig_20160329_be56801cfafaaad7b8c18d9e563efd74 {
  meta:
    description = "datamaliciousorder - file 20160329_be56801cfafaaad7b8c18d9e563efd74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce51632f8ada2bbe550c31ccebeba9a4eb68383e6c06eded7c19d154df9332e"

  strings:
    $s1  = "promise[throws + \"d\" + timerId] = ((21 - getAttributeNode) | (1 * doc));" fullword ascii
    $s2  = "if(requestHeaders[valHooks + \"tus\"] == ((dispatch - 2277) / (adown))) {" fullword ascii
    $s3  = "function forward(nodeValue, structure, script) {" fullword ascii
    $s4  = "multipleContexts(getAttributeNode, relative, createTextNode, dispatch, operator);" fullword ascii
    $s5  = "promise[\"Writ\" + timerId](requestHeaders[\"respon\" + rquickExpr]);" fullword ascii
    $s6  = "requestHeaders = qsaError[offsetParent + \"ipt\"][until + \"ateO\" + camel](sortInput[rnamespace]);" fullword ascii
    $s7  = "reliableMarginLeftVal(\"while%20%28requestHeaders%5Bdiv%20+%20%22tate%22%5D%20%21%3D%20%2811-%28dataShow%267%29%29%29%20qsaError" ascii
    $s8  = "reliableMarginLeftVal(\"while%20%28requestHeaders%5Bdiv%20+%20%22tate%22%5D%20%21%3D%20%2811-%28dataShow%267%29%29%29%20qsaError" ascii
    $s9  = "function classNames(using, triggerHandler, getScript) {" fullword ascii
    $s10 = "promise[\"t\" + dataUser + \"e\"] = (1 * fixHooks);" fullword ascii
    $s11 = "matcherFromGroupMatchers(jsonProp, operator, overflowX, beforeSend, curCSSTop);" fullword ascii
    $s12 = "notify(getElementById, stopImmediatePropagation, has, timer);" fullword ascii
    $s13 = "function getStyles(max, preFilters) {" fullword ascii
    $s14 = "forward(innerHTML, throws);" fullword ascii
    $s15 = "getStyles(rmouseEvent, timerId, fire);" fullword ascii
    $s16 = "reliableMarginLeftVal(\"wrap%20%3D%20fast%5B%22WScri%22%20+%20relative%5D%5B%22Crea%22%20+%20onlyHandlers%20+%20%22jec%22%20+%20" ascii
    $s17 = "promise[doScroll + \"e\" + sel]();" fullword ascii
    $s18 = "function reliableMarginLeftVal(xhrSupported) {" fullword ascii
    $s19 = "fast = qsaError = l = uid = qsa.lname();" fullword ascii
    $s20 = "function multipleContexts() {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}