rule sig_20160308_191c672786e9b2372e4deff230da5ca8 {
  meta:
    description = "datamaliciousorder - file 20160308_191c672786e9b2372e4deff230da5ca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a56c4e29fc37d84dc08fa3dd42cc89e5195a8eb274c2540fd7c5870343cee84b"

  strings:
    $x1  = "content = \"http:\", type = \"MSXML\", target = \"ngs\", setOffset = \"veT\", clearInterval = \"kao\", matcherFromTokens = 38;" fullword ascii
    $s2  = "removeEvent[innerHTML](err, content + delegate + clearInterval + marginLeft + setMatched + get + hooks + matches + marginRight, " ascii
    $s3  = "responseType = unqueued[statusText + getter + rdashAlpha + addEventListener + set + rpseudo + target](mouseHooks + settings + op" ascii
    $s4  = "rtypenamespace[contentDocument + operator + finalText + fromCharCode][guaranteedUnique + rwhitespace]((5 * context - 8645));" fullword ascii
    $s5  = "rtypenamespace[detectDuplicates + defineProperty + fromCharCode][speed + clientY](((Math.pow(addClass, 2) - defaultPrevented) / " ascii
    $s6  = "!(((((144 | setMatchers) & (5 ^ clientTop)), (4 | prevUntil) * 3, ((Math.pow(seed, 2) - combinator) + (91 + matcherFromTokens))," ascii
    $s7  = "responseType = unqueued[statusText + getter + rdashAlpha + addEventListener + set + rpseudo + target](mouseHooks + settings + op" ascii
    $s8  = "removeEvent[innerHTML](err, content + delegate + clearInterval + marginLeft + setMatched + get + hooks + matches + marginRight, " ascii
    $s9  = "replaceWith[appendTo + operator + rpseudo + fromCharCode + subordinate](removeEvent[compile + attrId]);" fullword ascii
    $s10 = "unqueued = username[rreturn + rsubmitterTypes + radio](contentDocument + l + boxSizingReliableVal + checkOn);" fullword ascii
    $s11 = "tions) + forward + leadingRelative + callbackContext + testContext + operator;" fullword ascii
    $s12 = "removeEvent = rtypenamespace[contentDocument + docElem + iterator][diff + documentIsHTML](type + rnoInnerhtml + jqXHR + sortDeta" ascii
    $s13 = "removeEvent = rtypenamespace[contentDocument + docElem + iterator][diff + documentIsHTML](type + rnoInnerhtml + jqXHR + sortDeta" ascii
    $s14 = "rtypenamespace = (((523 - sortStable) & (6401 / bup)), (((56 - reliableMarginRight) - (15 & checked)), this));" fullword ascii
    $s15 = "settings = \"TEMP%\";" fullword ascii
    $s16 = " ((987 / MAX_NEGATIVE) - (0 | rlocalProtocol))) & (2 * (submit ^ (2 | submit)) * (((20 - newDefer) * (0 ^ exports)) + ((11 / che" ascii
    $s17 = "unshift[margin + subordinate] = (exports * 3 * file / (108 / setMatchers));" fullword ascii
    $s18 = "rtypenamespace[detectDuplicates + defineProperty + fromCharCode][speed + clientY](((Math.pow(addClass, 2) - defaultPrevented) / " ascii
    $s19 = "fast[i](responseType.evt(), (truncate | 0), ((submit + 0) * truncate));" fullword ascii
    $s20 = "buildParams = \"sa\", getter = \"E\", docElem = \"ri\", Expr = \"op\", rsubmitterTypes = \"eO\", pixelMarginRightVal = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    1 of ($x*) and 4 of them
}