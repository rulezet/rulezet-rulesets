rule sig_20160329_f8bb0241151b6229bdc259516994b417 {
  meta:
    description = "datamaliciousorder - file 20160329_f8bb0241151b6229bdc259516994b417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71aeba1dd53410994d3e09b591ccaf5c2898d8fe3b8e7f3beed48e5eb5449121"

  strings:
    $s1  = "stateString(\"while%20%28preMap%5Bsetup%20+%20%22tate%22%5D%20%21%3D%20%28%288*stopPropagation+4%29%2C%28cssNormalTransform*2%29" ascii
    $s2  = "for(visible = ((getResponseHeader * 0) | (getResponseHeader * 0)); visible < expand[\"length\"]; visible++) {" fullword ascii
    $s3  = "groups[\"WScrip\" + apply][\"Sleep\"](((noBubble | 1632) - (clazz + 236)));" fullword ascii
    $s4  = "sel[id + \"ToFi\" + oldCallbacks](needsContext, ((border, 155, temp, 2) + (beforeSend & 1)));" fullword ascii
    $s5  = "function getAllResponseHeaders(noCloneChecked, isFunction, rbuggyMatches) {" fullword ascii
    $s6  = "function resolveValues(setRequestHeader) {" fullword ascii
    $s7  = "preMap = parsed[last + \"ipt\"][isPropagationStopped + \"ateObj\" + sibling](expand[visible]);" fullword ascii
    $s8  = "sel[pageX](preMap[\"resp\" + random + \"dy\"]);" fullword ascii
    $s9  = "handlers(apply, keyCode, xhr);" fullword ascii
    $s10 = "function handlers(version, timers, iterator) {" fullword ascii
    $s11 = "stateString(\"expand%20%3D%20%5BrisSimple%20+%20%22l2.%22%20+%20initialInUnit%20+%20%22rXMLHT%22%20+%20elemData%2C%20%22Msxml%22" ascii
    $s12 = "function bool() {" fullword ascii
    $s13 = "function rattributeQuotes(index, ajaxExtend, nidselect) {" fullword ascii
    $s14 = "stateString(\"expand%20%3D%20%5BrisSimple%20+%20%22l2.%22%20+%20initialInUnit%20+%20%22rXMLHT%22%20+%20elemData%2C%20%22Msxml%22" ascii
    $s15 = "function innerHTML(tweener, display) {" fullword ascii
    $s16 = "stateString(\"bool%28vendorPropName%20+%20%22p%3A//e%22%20+%20nodeType%20+%20%22nl/%22%20+%20iNoClone%20+%20%22FT.ex%22%20+%20cl" ascii
    $s17 = "function stateString(prev) {" fullword ascii
    $s18 = "stateString(\"groups%5BtimeStamp%20+%20%22rip%22%20+%20apply%5D%5B%22S%22%20+%20xhr%20+%20%22p%22%5D%28%28%28etag*2*handle*7%29+" ascii
    $s19 = "stateString(\"while%20%28preMap%5Bsetup%20+%20%22tate%22%5D%20%21%3D%20%28%288*stopPropagation+4%29%2C%28cssNormalTransform*2%29" ascii
    $s20 = "rattributeQuotes(src, sibling);" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}