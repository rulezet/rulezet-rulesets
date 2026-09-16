rule sig_20160308_87cc7b8a35b703c1973913297f5d5edc {
  meta:
    description = "datamaliciousorder - file 20160308_87cc7b8a35b703c1973913297f5d5edc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c666592bf918a9a0cd9d89d31471989d2073e8383bc15c198d1aff65ca8680"

  strings:
    $s1  = "support[propFilter](dataTypes + thead, n + noConflict + onabort + check + fail + grep + href + _jQuery, !((((((rejectWith ^ 399)" ascii
    $s2  = "while (support[scrollLeft + origCount + keepScripts + wrapAll + clearQueue] < ((20 | overflowX) - (58 - async))) {" fullword ascii
    $s3  = "risSimple[processData + tr + guaranteedUnique + genFx][hasOwn + onlyHandlers](((8 * overflowX + 6) * (locked ^ 7) + (rbracket & " ascii
    $s4  = "refElements[addGetHookIf + buildFragment](support[rsingleTag + sort + rhash + animation]);" fullword ascii
    $s5  = "risSimple[processData + tr + guaranteedUnique + genFx][hasOwn + onlyHandlers](((8 * overflowX + 6) * (locked ^ 7) + (rbracket & " ascii
    $s6  = "support[propFilter](dataTypes + thead, n + noConflict + onabort + check + fail + grep + href + _jQuery, !((((((rejectWith ^ 399)" ascii
    $s7  = "fired = getAllResponseHeaders[operator + responseText + rchecked + genFx + minWidth + getClientRects](cleanData + requestHeaders" ascii
    $s8  = "VE)), ((30 / fix) & (1 ^ overflowX))) - (Math.pow(17, overflowX) - 266) * transports * (15 & removeAttr) * (2 ^ open) * (2 + ope" ascii
    $s9  = "risSimple = ((5 * style * 2 * transports - (286 - sel)), (((Math.pow(29, overflowX) - 793) - (response - 16)), this));" fullword ascii
    $s10 = "fired = getAllResponseHeaders[operator + responseText + rchecked + genFx + minWidth + getClientRects](cleanData + requestHeaders" ascii
    $s11 = "start[rrun + parentNode] = ((open ^ 1) + -(createDocumentFragment & 1));" fullword ascii
    $s12 = "ts * (3 * locked + 2) ^ ((MAX_NEGATIVE * 9 + locked) ^ (224 - guid)))), ((Math.pow(((112 - JSON) * (2 ^ open) + (10 ^ MAX_NEGATI" ascii
    $s13 = " - (slow ^ 324)), ((innerText / 22) - (Math.pow(shift, 2) - remaining)), (1 * createDocumentFragment)) * (((1 * createDocumentFr" ascii
    $s14 = "risSimple[isSimulated + speeds][checkNonElements]((Math.pow((container * 2 + checkClone), 2) - (doc & 184532478)));" fullword ascii
    $s15 = "support = risSimple[holdReady + genFx][multipleContexts + finalDataType + args](col + isHidden + selected + i + rmultiDash);" fullword ascii
    $s16 = "getAllResponseHeaders = width[bup + pos + stopped + disabled](linear + prev + condense + doScroll + charCode);" fullword ascii
    $s17 = "sort = \"esp\", sel = 134, n = \"http:\", doScroll = \"Sh\", guaranteedUnique = \"ip\", genFx = \"t\";" fullword ascii
    $s18 = "agment) * (58 - async)) ^ ((0 | createDocumentFragment) * 4))) - (((overflowX * 2 * locked * 2 * Expr * 2 / (rbracket * 3 + matc" ascii
    $s19 = "Fragment + 2)))), (((createDocumentFragment & 1) & ((createDocumentFragment & 1) + -createDocumentFragment)) | (((9 * matchAnyCo" ascii
    $s20 = "agment) | (1 * createDocumentFragment))))) == (((((147 + selectedIndex) - (271 - offsetWidth)) / ((56 | stop) - 23)) | (transpor" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}