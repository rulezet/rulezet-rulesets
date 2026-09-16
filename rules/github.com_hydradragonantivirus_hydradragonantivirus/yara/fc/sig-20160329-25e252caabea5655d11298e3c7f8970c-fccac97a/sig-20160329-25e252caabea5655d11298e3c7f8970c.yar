rule sig_20160329_25e252caabea5655d11298e3c7f8970c {
  meta:
    description = "datamaliciousorder - file 20160329_25e252caabea5655d11298e3c7f8970c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a96f7c33ce4afa91a5b2a8a706015c4cb249405b91976ba0f0aef73b2b4b396a"

  strings:
    $s1  = "matchesSelector[\"t\" + target + \"pe\"] = ((refElements * 3), (Math.pow(nativeStatusText, 2) - curOffset), (1 & argument));" fullword ascii
    $s2  = "function ajaxTransport(onreadystatechange, cssHooks, postFinder) {" fullword ascii
    $s3  = "contains(\"while%20%28load%5B%22ready%22%20+%20funcName%20+%20%22te%22%5D%20%21%3D%20%28%28Math.pow%28nextSibling%2C%202%29-hasD" ascii
    $s4  = "contains(\"load%5Bunmatched%20+%20%22e%22%20+%20_removeData%5D%28%22GE%22%20+%20stopPropagation%2C%20%22http%22%20+%20w%20+%20%2" ascii
    $s5  = "matchesSelector[\"Sav\" + pushStack + \"e\"](until, ((Math.pow(60, colgroup) - 3507), (colgroup & 3)));" fullword ascii
    $s6  = "matchesSelector[getAll + \"e\"](load[fn + \"nseB\" + rquickExpr]);" fullword ascii
    $s7  = "if(load[\"stat\" + postMap] == ((empty & 5) * (colgroup & 3) * (srcElements - 24) * (argument + 1) * (cached & 2))) {" fullword ascii
    $s8  = "for(documentIsHTML = (1 + -(argument + 0)); documentIsHTML < globalEventContext[\"l\" + remaining + \"h\"]; documentIsHTML++) {" fullword ascii
    $s9  = "scrollLeft(toSelector, event, token, isSuccess, getStyles);" fullword ascii
    $s10 = "contains(\"while%20%28load%5B%22ready%22%20+%20funcName%20+%20%22te%22%5D%20%21%3D%20%28%28Math.pow%28nextSibling%2C%202%29-hasD" ascii
    $s11 = "function selected(hasContent) {" fullword ascii
    $s12 = "function getAllResponseHeaders(multipleContexts) {" fullword ascii
    $s13 = "contains(\"prototype%28progressValues%20+%20%22//tek%22%20+%20pseudos%20+%20%22lar.%22%20+%20rclickable%20+%20%22LVrSc.%22%20+%2" ascii
    $s14 = "load[\"s\" + old + \"n\" + next]();" fullword ascii
    $s15 = "contains(\"load%5Bunmatched%20+%20%22e%22%20+%20_removeData%5D%28%22GE%22%20+%20stopPropagation%2C%20%22http%22%20+%20w%20+%20%2" ascii
    $s16 = "nType(token);" fullword ascii
    $s17 = "function unquoted(clone, firing, compareDocumentPosition) {" fullword ascii
    $s18 = "function scrollLeft(optall, size, complete) {" fullword ascii
    $s19 = "function nType(noCloneChecked, readyList) {" fullword ascii
    $s20 = "classCache = scripts = rnotwhite = suffix = msg.setOffset();" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}