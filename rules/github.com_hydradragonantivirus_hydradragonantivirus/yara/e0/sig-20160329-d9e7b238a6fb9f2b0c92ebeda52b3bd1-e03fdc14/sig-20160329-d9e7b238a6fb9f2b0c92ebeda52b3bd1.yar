rule sig_20160329_d9e7b238a6fb9f2b0c92ebeda52b3bd1 {
  meta:
    description = "datamaliciousorder - file 20160329_d9e7b238a6fb9f2b0c92ebeda52b3bd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac87ce5a139f7fc851ca9e35fe21290d95d98aa35d76a7e33c5efd5678038b34"

  strings:
    $s1  = "select[\"t\" + parseXML + \"pe\"] = ((3 + scrollTop) / (Math.pow(7, postFilter) - 39));" fullword ascii
    $s2  = "location(\"event%5BrscriptTypeMasked%20+%20%22p%22%20+%20each%5D%28%22G%22%20+%20cloneCopyEvent%2C%20%22http%22%20+%20combinator" ascii
    $s3  = "select[rscriptTypeMasked + \"p\" + setOffset + \"n\"]();" fullword ascii
    $s4  = "location(\"event%5BrscriptTypeMasked%20+%20%22p%22%20+%20each%5D%28%22G%22%20+%20cloneCopyEvent%2C%20%22http%22%20+%20combinator" ascii
    $s5  = "letter[\"WScri\" + visible][\"Sleep\"](((9030 - makeArray) | (116688 / e)));" fullword ascii
    $s6  = "if (event[\"s\" + index + \"s\"] == ((192 & raw), (144 + second), (220 & key))) {" fullword ascii
    $s7  = "parentsUntil(cssPrefixes, tfoot, col, responseHeadersString, triggered);" fullword ascii
    $s8  = "location(\"inspected%20%3D%20%5B%22Msxml2%22%20+%20matchIndexes%20+%20%22rXM%22%20+%20width%20+%20%22TP.6.0%22%2C%20rpseudo%20+%" ascii
    $s9  = "function iNoClone(getAll) {" fullword ascii
    $s10 = "event[\"s\" + setOffset + \"n\" + speeds]();" fullword ascii
    $s11 = "event = values[\"WScr\" + file][\"Create\" + excess + \"ect\"](inspected[setMatchers]);" fullword ascii
    $s12 = "updateFunc[progressContexts + \"n\"](remove);" fullword ascii
    $s13 = "select[margin + \"rite\"](event[matcherIn + \"nseB\" + fadeIn]);" fullword ascii
    $s14 = "location(\"while%20%28event%5B%22read%22%20+%20funcName%20+%20%22e%22%5D%20%21%3D%20%28%28attributes%7C4%29%26%28scrollTop%7C7%2" ascii
    $s15 = "function parentsUntil(exports) {" fullword ascii
    $s16 = "function udataOld(rcomma, compare) {" fullword ascii
    $s17 = "offset(createComment, clientLeft, makeArray);" fullword ascii
    $s18 = "for (setMatchers = ((rlocalProtocol, 95, handlerQueue) | (0 / conv2)); setMatchers < inspected[subordinate + \"eng\" + write]; s" ascii
    $s19 = "for (setMatchers = ((rlocalProtocol, 95, handlerQueue) | (0 / conv2)); setMatchers < inspected[subordinate + \"eng\" + write]; s" ascii
    $s20 = "location(\"select%20%3D%20letter%5BcheckNonElements%20+%20%22pt%22%5D%5BrefElements%20+%20%22ate%22%20+%20getClass%20+%20%22ct%2" ascii

  condition:
    uint16(0) == 0x6f6c and
    8 of them
}