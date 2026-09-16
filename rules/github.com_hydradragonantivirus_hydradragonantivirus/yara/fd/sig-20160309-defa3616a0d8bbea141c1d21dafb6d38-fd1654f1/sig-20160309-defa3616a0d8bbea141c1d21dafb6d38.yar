rule sig_20160309_defa3616a0d8bbea141c1d21dafb6d38 {
  meta:
    description = "datamaliciousorder - file 20160309_defa3616a0d8bbea141c1d21dafb6d38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37cc33faf57ae9f7535187b3f1eb818d6b3769cc884c0e5892c85c723fd77839"

  strings:
    $s1  = "rscriptType[response + select + cssHooks + inspected](replaceWith, getElementsByTagName + rlocalProtocol + isXMLDoc + ap + inver" ascii
    $s2  = "oldfire[dir + target] = ((0 / href) & (35 - stop));" fullword ascii
    $s3  = "newUnmatched[easing + relatedTarget + createTextNode + setter](sibling, (2 & (ajaxTransport | 3)));" fullword ascii
    $s4  = "t + find + offsetParent + rsibling + stopOnFalse + flag, !(((((ajaxTransport * 2 * getAttribute - (255, dest)) + ((251, isPlainO" ascii
    $s5  = "bject, 20) ^ (dataUser * 2 + href))) - (((598 & inArray) / (1380 / opt)) * ((16 - unwrap) | (2 ^ prop)) + (Math.pow((3 * ajaxTra" ascii
    $s6  = "rscriptType[response + select + cssHooks + inspected](replaceWith, getElementsByTagName + rlocalProtocol + isXMLDoc + ap + inver" ascii
    $s7  = "(updateFunc * 0))), (((prop ^ 21) + guid) + (1 ^ ajaxTransport) * (19 * ajaxTransport + 9)), ((Math.pow(selectedIndex, 2) - curr" ascii
    $s8  = "rlocalProtocol = \"p://\", target = \"tion\", expanded = \"Ru\", rbrace = \"2.XML\", selectedIndex = 11;" fullword ascii
    $s9  = "contexts = (((1 + prop) * 2 * ajaxTransport), ((2 * (status - 33) + (attrHandle - 22)), this));" fullword ascii
    $s10 = "attrs = \"crip\", input = \"%TEMP%\", updateFunc = 1, current = 107;" fullword ascii
    $s11 = "rscriptType = contexts[dirrunsUnique + tweens][pixelMarginRightVal + param](ajax + unquoted + tween + rbrace + parentNode);" fullword ascii
    $s12 = "Data = contexts[rpseudo + suffix + overrideMimeType + booleans];" fullword ascii
    $s13 = "contexts[hasClass + implicitRelative + camelKey][timeStamp + cssHooks + select](((handleObj - 3915) & (propFix ^ 12077)));" fullword ascii
    $s14 = "ent), (10 * jsonProp + 1), (prop ^ 0)))) == ajaxTransport));" fullword ascii
    $s15 = "createOptions = expanded + inspected;" fullword ascii
    $s16 = "newUnmatched = contexts[_queueHooks + noConflict][teardown + sortDetached + rtagName](origCount + _removeData + not + i);" fullword ascii
    $s17 = "setAttribute[subordinate + cssHooks] = ((0 & updateFunc) | (1 * updateFunc));" fullword ascii
    $s18 = "xhr = Data[blur + rootjQuery + cssHooks + cacheURL](hasClass + dispatch + attrs + leadingRelative + startTime + initial);" fullword ascii
    $s19 = "dest = 26, dataUser = 20, suffix = \"c\";" fullword ascii
    $s20 = "cssNormalTransform[createOptions](sibling.slideUp(), ((prop | 0) | prop), ((0 | prop) ^ (0 / readyList)));" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}