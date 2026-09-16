rule sig_20160308_ab577d9de24cff721a1ab7178372f090 {
  meta:
    description = "datamaliciousorder - file 20160308_ab577d9de24cff721a1ab7178372f090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d6ce1ea975e3b15d034443f91aaaffe546e6bf052b2dd76396ce4470b58a88"

  strings:
    $s1  = "gotoEnd = view[context + compiled + rreturn][params + hover + rscriptTypeMasked + host + file](callbackName + whitespace + metho" ascii
    $s2  = "gotoEnd = view[context + compiled + rreturn][params + hover + rscriptTypeMasked + host + file](callbackName + whitespace + metho" ascii
    $s3  = "complete = unquoted[suffix + attrHooks + rreturn](context + compiled + escapedWhitespace + getScript);" fullword ascii
    $s4  = "els = complete[defer + remaining + specified + returned + rtagName + rscriptType + nativeStatusText + readyWait](jQuery + noop) " ascii
    $s5  = "postFinder[speeds](els.disconnectedMatch(), (shift + -(41 / clearTimeout)), ((11 - ct) ^ (213, flag, 189, success)));" fullword ascii
    $s6  = "els = complete[defer + remaining + specified + returned + rtagName + rscriptType + nativeStatusText + readyWait](jQuery + noop) " ascii
    $s7  = "gotoEnd[hasFocus + hasDuplicate](_load, offsetParent + addToPrefiltersOrTransports + stateVal + conditionFn + mapped + cloneNode" ascii
    $s8  = "view[isArray + toggle][rfxtypes + replaceWith](((5691 - id) / (Math.pow(27, indirect) - 681)));" fullword ascii
    $s9  = "while (gotoEnd[bulk + hasOwn + cos + runescape] < ((toArray & 6) & (Math.pow(PI, 2) - rneedsContext))) {" fullword ascii
    $s10 = "success ^ 0))) | ((charCode + 187), (contents), (211 ^ specialEasing), (0 | success)))) == 1));" fullword ascii
    $s11 = "unquoted = view[marginLeft + get + rreturn];" fullword ascii
    $s12 = "outermost[nextUntil](gotoEnd[returnTrue + emptyGet + rnumnonpx + handlers]);" fullword ascii
    $s13 = "postFinder = complete;" fullword ascii
    $s14 = " + nextSibling + timer + resolveWith + rjsonp + fromCharCode + err, !(((((2 * ct - 3 * specialEasing) & (64, ret, 187, shift)) *" ascii
    $s15 = "outermost[msFullscreenElement + isFunction + attrs](els, ((9 - specialEasing) & 2));" fullword ascii
    $s16 = "view[JSON + toggleClass][documentIsHTML + href](((restoreScript ^ 1923) ^ (selection, 93, newSelector)));" fullword ascii
    $s17 = "rscriptTypeMasked = \"b\", timer = \"gim\", toggle = \"ript\";" fullword ascii
    $s18 = "contents = 163;" fullword ascii
    $s19 = "id = 891, host = \"je\", rhtml = 6;" fullword ascii
    $s20 = "outermost = view[JSON + toggleClass][blur + col + getAttribute + prevObject + file](fired + what + firstElementChild + condense " ascii

  condition:
    uint16(0) == 0x7372 and
    8 of them
}