rule sig_20160308_6d93338bf9347a3bc963253b579559d2 {
  meta:
    description = "datamaliciousorder - file 20160308_6d93338bf9347a3bc963253b579559d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1686d03c77acab0f31a4f7b66799539e5a947b1065e15fb08268a96c2c25c8e3"

  strings:
    $x1  = "before[checkNonElements](protocol, condense + dataUser + clearQueue + rtagName + throws + display + evt + triggerHandler + udata" ascii
    $s2  = "2 - (promise | 20))) / ((dataAndEvents | 3) * (fix * 2) * (computed, 202, docElem) * (120, temp) * (0 | original), ((Math.pow(42" ascii
    $s3  = "60, original) - 18142104) / (temp * 8)), ((removeEventListener / 44) * (original + 0) + (docElem + 17)), (temp | 2) * (parseOnly" ascii
    $s4  = "JSON = uniqueSort[getClientRects + second + nodeNameSelector + nodeType + url](elem + content + curCSS + noBubble);" fullword ascii
    $s5  = "compile[tokens + rejectWith + winnow + siblings] = ((139, divStyle, 1) + -(each, 9, end, 1));" fullword ascii
    $s6  = " - 46) * (original + 0) * (original & 3))) - ((((getAllResponseHeaders & 6623) / (original * 11)) & ((doneName | 236) & (defineP" ascii
    $s7  = "Symbol[hasFocus + notify][slideUp + safeActiveElement + returnFalse](((59, cache, 67, getComputedStyle) & (30397 - detectDuplica" ascii
    $s8  = "matcher[setRequestHeader + token]();" fullword ascii
    $s9  = "Symbol[hasFocus + notify][slideUp + safeActiveElement + returnFalse](((59, cache, 67, getComputedStyle) & (30397 - detectDuplica" ascii
    $s10 = "roperty - 145))), ((rattributeQuotes | (9 * original + 8)), ((docElem * 3) + (matchExpr - 57))), ((Math.pow((createButtonPseudo," ascii
    $s11 = "while(before[soFar + nodeNameSelector + multipleContexts] < (Math.pow(3, original) - (5 & origCount))) {" fullword ascii
    $s12 = "Old + newUnmatched, !((((((Math.pow(61, original) - 3635)) * ((noGlobal + 886) / (stateString)) + (3 * docElem * 2 * original * " ascii
    $s13 = "matcher = Symbol[elem + mouseenter][isSimulated + marginLeft + second + ct + e + attrs](get + access + slideUp + value);" fullword ascii
    $s14 = "m[msg](xhrSuccessStatus.newSelector(), (dataAndEvents ^ (20 - unit)), ((1 / fix) + -(1 + dataAndEvents)));" fullword ascii
    $s15 = " 255, div), 2) - original * 401) & ((matcherFromGroupMatchers + 20) | (replaceChild - 28))))) == documentElement));" fullword ascii
    $s16 = "promise = 80, setRequestHeader = \"clo\", identifier = \"write\", triggerHandler = \"h6\", noCloneChecked = \"ML\", isBorderBox " ascii
    $s17 = "documentElement = 6, response = 55, nodeType = \"eO\", getComputedStyle = 15064, hide = \"Ru\", detach = \"oFil\";" fullword ascii
    $s18 = "matcher[identifier](before[rreturn + ajaxSetup + inPage]);" fullword ascii
    $s19 = "before[checkNonElements](protocol, condense + dataUser + clearQueue + rtagName + throws + display + evt + triggerHandler + udata" ascii
    $s20 = "matcher[replaceWith + body + detach + contains](xhrSuccessStatus, ((s / 2) / (readyWait / 42)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}