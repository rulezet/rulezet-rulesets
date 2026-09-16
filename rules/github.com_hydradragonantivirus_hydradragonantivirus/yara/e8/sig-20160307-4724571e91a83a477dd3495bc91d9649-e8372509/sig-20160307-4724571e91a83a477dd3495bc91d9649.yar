rule sig_20160307_4724571e91a83a477dd3495bc91d9649 {
  meta:
    description = "datamaliciousorder - file 20160307_4724571e91a83a477dd3495bc91d9649.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efccb292ade6bf6d864975419a22cd65302d7b62f7857acdaa5b07bf4d5f440"

  strings:
    $s1  = "contains[top](clone, superMatcher + special + offset + animated + tokens + updateFunc + animate + scrollTo + slideToggle + reset" ascii
    $s2  = " ^ 15) & (Math.pow(elems, 2) - errorCallback)) & (11 | (after + 12)))) ^ ((((refElements | 86) - getElementById * 2) * ((dataSho" ascii
    $s3  = "rwhitespace = (((1345 * wrap + 1327) / (cors / 50)), (((getScript & 121), pointerleave * 17 * pointerleave, 62, fontWeight * 2 *" ascii
    $s4  = "rwhitespace = (((1345 * wrap + 1327) / (cors / 50)), (((getScript & 121), pointerleave * 17 * pointerleave, 62, fontWeight * 2 *" ascii
    $s5  = "/ 24) / (matcherFromTokens - 30)) * ((transport | 32), (origName & 6)) + (orig / 38) * (dataShow | 2) * (_$ - 8) * (_queueHooks " ascii
    $s6  = "contains = rwhitespace[relative + wait][firing + one](r20 + responseType + relatedTarget + returned);" fullword ascii
    $s7  = "- 25)), (((dataShow & 1) ^ (dataShow & 1)) ^ ((timer * 2 + wrap) - (Math.pow(15, fontWeight) - 205))))) > timeStamp));" fullword ascii
    $s8  = "rwhitespace[stored + addClass][clientX + nidselect + reliableMarginLeftVal]((wrap & 7) * (readyList, 5) * (after * 5) * (param, " ascii
    $s9  = "origName = 7, param = 146, nidselect = \"le\", updateFunc = \"ra.com\", originalProperties = \"sen\";" fullword ascii
    $s10 = "while (contains[parseXML + winnow] < ((42 - cssFn) & (5 + after))) {" fullword ascii
    $s11 = "  cssPrefixes[access + type + docElem] = ((1 ^ pointerleave) - 2);" fullword ascii
    $s12 = "_queueHooks = 27, seekingTransport = \"ript\", animate = \".a\", matchAnyContext = \"Expan\", clone = \"GET\", offset = \"//\";" fullword ascii
    $s13 = "  complete[addGetHookIf](raw.emptyGet(), ((dataShow | 0) / (matchesSelector & 23)), dataShow);" fullword ascii
    $s14 = "raw = index[matchAnyContext + hide + assert + rpseudo + finalDataType + setFilters + scrollLeft + merge + constructor](onload + " ascii
    $s15 = "index = defineProperty[createFxNow + parsed + using](send + valueIsBorderBox + seekingTransport + scrollTop + marginRight + pars" ascii
    $s16 = "contains[top](clone, superMatcher + special + offset + animated + tokens + updateFunc + animate + scrollTo + slideToggle + reset" ascii
    $s17 = "index = defineProperty[createFxNow + parsed + using](send + valueIsBorderBox + seekingTransport + scrollTop + marginRight + pars" ascii
    $s18 = "  special = \"p:\"," fullword ascii
    $s19 = "  send = (function Object.prototype.emptyGet() {" fullword ascii
    $s20 = "  clearQueue[display + bySet] = ((after + 0) + dataShow);" fullword ascii

  condition:
    uint16(0) == 0x715f and
    8 of them
}