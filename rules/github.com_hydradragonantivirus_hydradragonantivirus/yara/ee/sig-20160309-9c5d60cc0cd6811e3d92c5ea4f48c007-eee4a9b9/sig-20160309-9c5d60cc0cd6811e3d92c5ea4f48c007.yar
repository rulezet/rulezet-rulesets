rule sig_20160309_9c5d60cc0cd6811e3d92c5ea4f48c007 {
  meta:
    description = "datamaliciousorder - file 20160309_9c5d60cc0cd6811e3d92c5ea4f48c007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d5fa6be7f93953e5a56f8718926dde8e9595a266c2e546ef69cb83746b4ccb6"

  strings:
    $s1  = "_evalUrl[setOffset + handlers + until](createInputPseudo + postFinder, curOffset + leadingRelative + scrollTop + isSuccess + ins" ascii
    $s2  = "split = last[completeDeferred + rhtml][XMLHttpRequest + getComputedStyle + handlers + nodeName](targets + settings + linear + ma" ascii
    $s3  = "split = last[completeDeferred + rhtml][XMLHttpRequest + getComputedStyle + handlers + nodeName](targets + settings + linear + ma" ascii
    $s4  = "seed = wrap[processData + linear + exports + what + values + nodeName](mouseenter + inPage + init + hasScripts);" fullword ascii
    $s5  = "cumentFragment & (Math.pow(53, parseOnly) - 2706))) ^ (Math.pow(((scripts & 7) ^ (image - 74)), ((clone) * (0 ^ parseOnly))) - (" ascii
    $s6  = "opyIsArray, !(parsed < (Math.pow((Math.pow(((0 | (nonce / 21)) + ((clone | 0) * (parseOnly * 3 + clone))), (((38 - tfoot) | (Mat" ascii
    $s7  = "doc[rrun + optgroup + rhtml + unshift] = ((delay / 41) * (clone + -1));" fullword ascii
    $s8  = "last = (((70, newSelector) | 5 * parseOnly * 13), ((Math.pow((createDocumentFragment & 13), (clone + 1)) - (locked / 19)), this)" ascii
    $s9  = "_evalUrl = last[mouseenter + parentNode + rhtml][processData + els + duplicates + addHandle](cur + status + radio + removeAttrib" ascii
    $s10 = "last = (((70, newSelector) | 5 * parseOnly * 13), ((Math.pow((createDocumentFragment & 13), (clone + 1)) - (locked / 19)), this)" ascii
    $s11 = "_evalUrl = last[mouseenter + parentNode + rhtml][processData + els + duplicates + addHandle](cur + status + radio + removeAttrib" ascii
    $s12 = "wrap = last[createHTMLDocument + rscriptTypeMasked];" fullword ascii
    $s13 = "camel = seed[returnFalse + easing + dataPriv + etag + text + matchContext + manipulationTarget + selector](aup + dataAndEvents) " ascii
    $s14 = "camel = seed[returnFalse + easing + dataPriv + etag + text + matchContext + manipulationTarget + selector](aup + dataAndEvents) " ascii
    $s15 = "overflow = 7882, targets = \"AD\";" fullword ascii
    $s16 = "pectPrefiltersOrTransports + ignored + readyList + offsetParent + linear + isImmediatePropagationStopped + progress + winnow + c" ascii
    $s17 = "last[flag + whitespace + rscriptTypeMasked][hookFn + ct](((2228 ^ overflow) * 2 + (dispatch / 46)));" fullword ascii
    $s18 = "_evalUrl[setOffset + handlers + until](createInputPseudo + postFinder, curOffset + leadingRelative + scrollTop + isSuccess + ins" ascii
    $s19 = "contents[parts + appendTo]();" fullword ascii
    $s20 = "split[getText + until]();" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}