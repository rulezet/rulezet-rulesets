rule sig_20160308_84374bb0c456e7e95e01d3f719ececca {
  meta:
    description = "datamaliciousorder - file 20160308_84374bb0c456e7e95e01d3f719ececca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8764281215482528b3a60e933d4e24b65dcba95d815bc28e85a3756a7fc2945"

  strings:
    $s1  = "matcherFromTokens = getWindow[hookFn + writable + disableScript + nextSibling][slideUp + pipe + selector + pseudos](parseHTML + " ascii
    $s2  = "matcherFromTokens = getWindow[hookFn + writable + disableScript + nextSibling][slideUp + pipe + selector + pseudos](parseHTML + " ascii
    $s3  = "valueIsBorderBox = owner[ajax + _removeData + rnamespace + hasScripts + guaranteedUnique + nextSibling + contexts + defaultPreve" ascii
    $s4  = "matcherFromTokens[setAttribute](parent, high + firstElementChild + conv2 + binary + delegateType + computeStyleTests + obj + get" ascii
    $s5  = "getWindow[rrun + responseType][reliableMarginLeftVal + initial]((Math.pow((charset * 145 + notify), 2) - (showHide | 135343652))" ascii
    $s6  = "getWindow[rrun + responseType][reliableMarginLeftVal + initial]((Math.pow((charset * 145 + notify), 2) - (showHide | 135343652))" ascii
    $s7  = "nted](ap + tag) + ofType + PI + requestHeadersNames + compare + textContent + percent + writable;" fullword ascii
    $s8  = "getWindow = (((Math.pow(5, cloneCopyEvent) - 16) ^ (appendChild * 2 + pnum)), ((1 & (cssHooks & 1)), this));" fullword ascii
    $s9  = "matcherFromTokens[setAttribute](parent, high + firstElementChild + conv2 + binary + delegateType + computeStyleTests + obj + get" ascii
    $s10 = "owner = Data[insertBefore + curElem + nextSibling](rrun + responseType + style + inspectPrefiltersOrTransports);" fullword ascii
    $s11 = "valueIsBorderBox = owner[ajax + _removeData + rnamespace + hasScripts + guaranteedUnique + nextSibling + contexts + defaultPreve" ascii
    $s12 = "while(matcherFromTokens[readyWait + inspect] < ((3 + username) & (4 ^ curCSSLeft))) {" fullword ascii
    $s13 = "Data = getWindow[optionSet + tuples];" fullword ascii
    $s14 = "disableScript = \"ip\", querySelectorAll = \"ile\", lastChild = 33, height = \"HTTP\";" fullword ascii
    $s15 = "booleans = getWindow[optionSet + rmouseEvent + nextSibling][delegateCount + testContext + curElem + nextSibling](tuple + next + " ascii
    $s16 = "booleans[oldfire + l](matcherFromTokens[defer + set + all]);" fullword ascii
    $s17 = "matcherFromTokens[defaultPrevented + guaranteedUnique + condense]();" fullword ascii
    $s18 = "var pipe = \"teOb\"," fullword ascii
    $s19 = "booleans = getWindow[optionSet + rmouseEvent + nextSibling][delegateCount + testContext + curElem + nextSibling](tuple + next + " ascii
    $s20 = "writable = \"cr\", parent = \"GET\", next = \"DODB.\", selector = \"je\", condense = \"d\";" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}