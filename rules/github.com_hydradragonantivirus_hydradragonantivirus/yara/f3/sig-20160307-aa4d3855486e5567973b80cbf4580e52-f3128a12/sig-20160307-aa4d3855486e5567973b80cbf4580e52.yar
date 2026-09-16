rule sig_20160307_aa4d3855486e5567973b80cbf4580e52 {
  meta:
    description = "datamaliciousorder - file 20160307_aa4d3855486e5567973b80cbf4580e52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9034d34cca979126bebe7c5fde2ded35997aad8c11b44c055a850bffbb078d4"

  strings:
    $s1  = "rheader[extra](configurable.isHidden(), ((1 + -end) / (Math.pow(14, valueIsBorderBox) - 171)), ((end & 1) + -end));" fullword ascii
    $s2  = "cos = hold[before + styles + first + contents](computeStyleTests + selected + locked + key + originalSettings + originalSettings" ascii
    $s3  = "cos = hold[before + styles + first + contents](computeStyleTests + selected + locked + key + originalSettings + originalSettings" ascii
    $s4  = "xhrSupported = \"GET\", dataTypes = \"%TEMP\", bulk = \"op\", flag = \"pen\", fire = \"ADODB\", opacity = 17;" fullword ascii
    $s5  = "each[visibility + wrapMap + getElementsByTagName + contents + createTween] = ((mouseenter, 187, returnTrue), 3 * opacity, (0 & e" ascii
    $s6  = "each[visibility + wrapMap + getElementsByTagName + contents + createTween] = ((mouseenter, 187, returnTrue), 3 * opacity, (0 & e" ascii
    $s7  = "configurable = cos[implementation + nonce + inspect + outermost + class2type + isEmptyObject](dataTypes + curElem) + targets + s" ascii
    $s8  = "configurable = cos[implementation + nonce + inspect + outermost + class2type + isEmptyObject](dataTypes + curElem) + targets + s" ascii
    $s9  = "tokens[host + jsonProp] = ((keepData ^ 1) | (end * 0));" fullword ascii
    $s10 = "progressValues[addEventListener + result][delay + unit](((ajaxPrefilter - 7253)));" fullword ascii
    $s11 = "progressValues = ((2 | keepData) * (17 | keepData) * (1 ^ protocol) * (65, valueIsBorderBox) * (42 - types), (((28 * i + 21), (i" ascii
    $s12 = "sFunction / 47), (Math.pow(rattributeQuotes, 2) - parents), (Math.pow(6, valueIsBorderBox) - 26)), this));" fullword ascii
    $s13 = "progressValues[pixelMarginRight + checked + contents][delay + unit](((allTypes & 115), (size, 113), (source ^ 35)));" fullword ascii
    $s14 = "extra = documentIsHTML + postMap;" fullword ascii
    $s15 = "mapped = progressValues[setMatched + contents][now + setMatcher + rparentsprev](fire + matches + optall + reliableMarginRight + " ascii
    $s16 = "achEvent + attrHooks + charCode + divStyle, !(uniqueSort < (((((1 * keepData) | (41 & parentOffset)))) - ((5 * protocol + 2) | (" ascii
    $s17 = "progressValues = ((2 | keepData) * (17 | keepData) * (1 ^ protocol) * (65, valueIsBorderBox) * (42 - types), (((28 * i + 21), (i" ascii
    $s18 = "detectDuplicates[bulk + rtypenamespace](xhrSupported, currentTime + offsetHeight + locked + inPage + wrapMap + speed + idx + att" ascii
    $s19 = "match = \"Out\", targets = \"f\", scale = \"P\", cacheURL = \"S\", to = \"XML2.X\";" fullword ascii
    $s20 = "host = \"ty\";" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}