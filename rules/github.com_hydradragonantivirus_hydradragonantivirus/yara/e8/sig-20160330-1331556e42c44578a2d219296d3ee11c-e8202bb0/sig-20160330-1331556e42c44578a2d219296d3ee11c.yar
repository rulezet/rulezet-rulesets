rule sig_20160330_1331556e42c44578a2d219296d3ee11c {
  meta:
    description = "datamaliciousorder - file 20160330_1331556e42c44578a2d219296d3ee11c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f0087e51d6ddfba9b93f99199f8c13c236ad6561c7b82707a6d61dd517b5c2c"

  strings:
    $s1  = "method(\"needsContext&20&3D&20&5B&22Msxml2&22&20+&20doScroll&20+&20&22rverXM&22&20+&20Data&20+&20&22.6.0&22&2C&20doneName&20+&20" ascii
    $s2  = "disableScript(to, visible, tokens, multipleContexts, deep);" fullword ascii
    $s3  = "for(token = (1 * ownerDocument); token < needsContext[\"len\" + to + \"h\"]; token++) {" fullword ascii
    $s4  = "function disableScript(empty) {" fullword ascii
    $s5  = "function click(rscriptType, charset) {" fullword ascii
    $s6  = "contents(conditionFn, ownerDocument, multipleContexts, expando);" fullword ascii
    $s7  = "function contents(cloneCopyEvent, special, val) {" fullword ascii
    $s8  = "scale[rxhtmlTag + \"yp\" + position] = ((17 / postFinder) + (0 / innerText));" fullword ascii
    $s9  = "if(soFar[\"s\" + cssProps + \"tus\"] == ((scrollLeft * 5) * (keepData) * (1 * rtrim) * (77, constructor, 2) * (doAnimation / 29)" ascii
    $s10 = "escaped[currentValue + \"rip\" + rxhtmlTag][\"Sle\" + source](((parent - 297) / (keepData & 6)));" fullword ascii
    $s11 = "method(\"index&28&22http&22&20+&20global&20+&20&22undo&22&20+&20expando&20+&20&22oso&22&20+&20define&20+&20&22br/&22&20+&20elemD" ascii
    $s12 = "method(\"soFar&5BmultipleContexts&20+&20&22p&22&20+&20writable&5D&28&22G&22&20+&20nodeNameSelector&2C&20&22http&3A&22&20+&20suff" ascii
    $s13 = "method(\"soFar&5BmultipleContexts&20+&20&22p&22&20+&20writable&5D&28&22G&22&20+&20nodeNameSelector&2C&20&22http&3A&22&20+&20suff" ascii
    $s14 = "function inspected(binary, fontWeight) {" fullword ascii
    $s15 = "method(\"location&20&3D&20evt&5B&22Expan&22&20+&20toggle&20+&20&22vironm&22&20+&20camelCase&20+&20&22Stri&22&20+&20rnoInnerhtml&" ascii
    $s16 = "function responses(nodeType, proxy) {" fullword ascii
    $s17 = "method(\"index&28&22http&22&20+&20global&20+&20&22undo&22&20+&20expando&20+&20&22oso&22&20+&20define&20+&20&22br/&22&20+&20elemD" ascii
    $s18 = "method(\"soFar&20&3D&20escaped&5BcurrentValue&20+&20&22rip&22&20+&20rxhtmlTag&5D&5B&22Crea&22&20+&20readyList&20+&20&22ect&22&5D" ascii
    $s19 = "function responseText() {" fullword ascii
    $s20 = "scale[namespaces](soFar[\"res\" + parents + \"seBody\"]);" fullword ascii

  condition:
    uint16(0) == 0x6877 and
    8 of them
}