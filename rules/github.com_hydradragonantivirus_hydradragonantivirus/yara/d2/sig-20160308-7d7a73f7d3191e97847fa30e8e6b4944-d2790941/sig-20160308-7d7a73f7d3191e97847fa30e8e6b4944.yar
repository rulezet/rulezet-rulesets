rule sig_20160308_7d7a73f7d3191e97847fa30e8e6b4944 {
  meta:
    description = "datamaliciousorder - file 20160308_7d7a73f7d3191e97847fa30e8e6b4944.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa69c2918901062aa85087ed11e971abe86ced8298fd573becb2b5dcf6854ca"

  strings:
    $s1  = "conv[checkbox + s](rscriptTypeMasked + fontWeight, pos + animate + fxNow + teardown + argument + ajaxTransport + isArray + point" ascii
    $s2  = "headers = cssFn[readyWait + rjsonp + hasContent + append + postFilter + url + values + doScroll + when + wrap](Symbol + valueIsB" ascii
    $s3  = "headers = cssFn[readyWait + rjsonp + hasContent + append + postFilter + url + values + doScroll + when + wrap](Symbol + valueIsB" ascii
    $s4  = "rnotwhite[rheader + strAbort + setTimeout + origFn](headers, ((Math.pow(parentWindow, 2) - nodes) / (6 / merge)));" fullword ascii
    $s5  = "conv = attr[_removeData + contentType + elementMatcher][pdataCur + addGetHookIf + curTop](stop + rpseudo + rsingleTag + rpseudo " ascii
    $s6  = "while (conv[replaceWith + origFn + clearTimeout + script + initialInUnit] < ((merge + -1) ^ (evt * 2))) {" fullword ascii
    $s7  = "conv = attr[_removeData + contentType + elementMatcher][pdataCur + addGetHookIf + curTop](stop + rpseudo + rsingleTag + rpseudo " ascii
    $s8  = "conv[checkbox + s](rscriptTypeMasked + fontWeight, pos + animate + fxNow + teardown + argument + ajaxTransport + isArray + point" ascii
    $s9  = "opacity[rheaders + rcombinators] = ((merge & 1) * (fast / 13));" fullword ascii
    $s10 = "erenter + parseFromString + noop, !(((((7770 / nodes), (83 * evt + 22), (funcName * 6 + rmsPrefix), (5 + dataShow)) * ((72 - key" ascii
    $s11 = "attr[style + elementMatcher][lang + w](((div1 * 2 + tokens) - 53));" fullword ascii
    $s12 = "attr = ((7 & parentWindow) * (18 / getElementsByName), (((0 & merge) / (986 / dataAttr)), this));" fullword ascii
    $s13 = "rnotwhite[head](conv[unshift + removeEventListener + cache]);" fullword ascii
    $s14 = "& merge)))) == ((((15 ^ _evalUrl) & (27 ^ dataTypeExpression)) - ((799 - base) / (1088 / using))) + ((((2 * lastModified) * (50 " ascii
    $s15 = ") - (4 ^ jQuery)) / (((2 | fast) * 2 + merge) ^ (3 * firstChild + 1))) * (((fadeIn ^ 54) - evt * 5 * fadeIn) + ((1 + fast) * (0 " ascii
    $s16 = "script = \"ta\";" fullword ascii
    $s17 = "dataTypeExpression = 4, whitespace = \"heigh\", dataAttr = 29, append = \"En\", head = \"write\";" fullword ascii
    $s18 = "factory[iNoClone](headers.destElements(), (0 ^ (originalProperties, 0)), ((fast | 0) & (fast | 0)));" fullword ascii
    $s19 = "isArray = \"9\", getElementsByName = (function Object.prototype.destElements() {" fullword ascii
    $s20 = "isArrayLike = attr[suffix + radioValue + elementMatcher];" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}