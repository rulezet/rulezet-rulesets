rule sig_20160330_fb1be6c0de4a34136bf02d7ed497d9f8 {
  meta:
    description = "datamaliciousorder - file 20160330_fb1be6c0de4a34136bf02d7ed497d9f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96cebb71d31f0d4fab4423b13e1725b430a574d11cd01adcee7bde8faf0d70fb"

  strings:
    $s1  = "eval(unescape([\"ajaxPrefilter&20&3D&20&28&22VAZ.e&22&29&2C&20tmp&20&3D&20&28&22ml2&22&29&2C&20createButtonPseudo&20&\", \"3D&20" ascii
    $s2  = "properties[getter + \"de\"] = ((13 * collection * 5), (Math.pow(display, 2) - special), (3 & collection));" fullword ascii
    $s3  = "properties[contents + \"p\" + defineProperty]();" fullword ascii
    $s4  = "xhrFields(\"while&20&28defer&5B&22read&22&20+&20createPseudo&5D&20&21&3D&20&28&28211&2Cbind&29&26&282*dataUser&29&29&29&20rcheck" ascii
    $s5  = "xhrFields(\"while&20&28defer&5B&22read&22&20+&20createPseudo&5D&20&21&3D&20&28&28211&2Cbind&29&26&282*dataUser&29&29&29&20rcheck" ascii
    $s6  = "for (cors = (1 + -(inspected & 1)); cors < adjustCSS[splice + \"ng\" + guid]; cors++) {" fullword ascii
    $s7  = "function opts(multipleContexts, unbind, rnoContent) {" fullword ascii
    $s8  = "unique(pageX, bind, responseHeadersString, childNodes, createButtonPseudo);" fullword ascii
    $s9  = "if (defer[prevObject + \"us\"] == ((154, isEmptyObject, 28) + (overflow - 191))) {" fullword ascii
    $s10 = "defer[global + \"n\" + rcomma]();" fullword ascii
    $s11 = "properties[\"Save\" + traditional](map, ((dataUser & 3) | (dataUser | 2)));" fullword ascii
    $s12 = "properties[\"Write\"](defer[dataTypeOrTransport + \"seBod\" + flatOptions]);" fullword ascii
    $s13 = "xhrFields(\"apply&28&22http&22&20+&20rfxtypes&20+&20&22ownl&22&20+&20boolHook&20+&20&22root.&22&20+&20matcherIn&20+&20&22/vU&22&" ascii
    $s14 = "function append(restoreScript, PI, eased) {" fullword ascii
    $s15 = "xhrFields(\"apply&28&22http&22&20+&20rfxtypes&20+&20&22ownl&22&20+&20boolHook&20+&20&22root.&22&20+&20matcherIn&20+&20&22/vU&22&" ascii
    $s16 = "function contentType(selectors, preDispatch, href) {" fullword ascii
    $s17 = "_jQuery(originAnchor, funcName, responseHeadersString, detach);" fullword ascii
    $s18 = "_default[\"WScrip\" + preFilters][\"S\" + splice + \"ep\"](((parent & 6142) & (firstDataType | 4492)));" fullword ascii
    $s19 = "bindType = parse = _default = rchecked = progressValues.stored();" fullword ascii
    $s20 = "xhrFields(\"defer&5B&22o&22&20+&20rinputs&20+&20&22en&22&5D&28funcName&20+&20&22T&22&2C&20visibility&20+&20&22/down&22&20+&20hoo" ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}