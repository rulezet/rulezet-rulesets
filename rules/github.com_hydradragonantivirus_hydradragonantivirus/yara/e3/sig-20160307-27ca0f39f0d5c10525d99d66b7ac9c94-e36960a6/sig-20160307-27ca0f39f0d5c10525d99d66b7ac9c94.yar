rule sig_20160307_27ca0f39f0d5c10525d99d66b7ac9c94 {
  meta:
    description = "datamaliciousorder - file 20160307_27ca0f39f0d5c10525d99d66b7ac9c94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ac2d7980bca50a1d97304df163141d83b475252b085b58ea96ec425102316e"

  strings:
    $s1  = "rnoInnerhtml[responseType + event](selected, dest + cacheURL + guaranteedUnique + trigger + rnotwhite + a + qsa + combinator + r" ascii
    $s2  = " run[contains](removeData.removeChild(), (trim - 4), (getScript * 0));" fullword ascii
    $s3  = "scriptType + stop, !(1 == ((((getScript * 0) ^ matchExpr) / 2 * (computed + 0) * (minWidth, 236, originalProperties, 5)) | (((ma" ascii
    $s4  = "domManip = (((Math.pow(1637, computed) - 2678119) / (curPosition & 29)), (((Math.pow(qsaError, 2) - fontWeight) + (0 | trim)), t" ascii
    $s5  = "domManip = (((Math.pow(1637, computed) - 2678119) / (curPosition & 29)), (((Math.pow(qsaError, 2) - fontWeight) + (0 | trim)), t" ascii
    $s6  = "domManip[rmsPrefix + rinputs + reset][serializeArray + then](((Math.pow(3738, computed) - 13968020) | (win - 9978)));" fullword ascii
    $s7  = " domManip[sel + addBack + i][readyState + stopPropagation]((Math.pow((191 - disabled), (43 - uniqueID)) - (268 | throws)));" fullword ascii
    $s8  = "curPosition = 25, win = 20866, qsaError = 5, wrapAll = \"ipt.Sh\", script = \"cr\", compiled = \"MSXML2\";" fullword ascii
    $s9  = "while(rnoInnerhtml[args + fadeTo + selector + startLength] < ((22 - stopped) * (1 ^ qsaError))) {" fullword ascii
    $s10 = " vendorPropName = \"%TEMP%\"," fullword ascii
    $s11 = "rnoInnerhtml = domManip[els + i][tokenize + matchedCount + teardown](compiled + runescape + overflow + text + bool);" fullword ascii
    $s12 = " map[PI + splice](removeData, (isXML - 11));" fullword ascii
    $s13 = "map = domManip[winnow + tokenCache + i][isSimulated + createInputPseudo + teardown](hasClass + textContent + newCache + sort + s" ascii
    $s14 = "map = domManip[winnow + tokenCache + i][isSimulated + createInputPseudo + teardown](hasClass + textContent + newCache + sort + s" ascii
    $s15 = " has[version] = (notify * 2, (matchExpr ^ 1));" fullword ascii
    $s16 = "removeData = off[defaultDisplay + register + isImmediatePropagationStopped + uniqueSort + outermost + href](vendorPropName + nod" ascii
    $s17 = "off = cors[round + pnum + optSelected](winnow + script + wrapAll + toggleClass);" fullword ascii
    $s18 = "selected = \"GET\";" fullword ascii
    $s19 = " map[colgroup + async](rnoInnerhtml[elementMatcher + optgroup + copy]);" fullword ascii
    $s20 = "removeData = off[defaultDisplay + register + isImmediatePropagationStopped + uniqueSort + outermost + href](vendorPropName + nod" ascii

  condition:
    uint16(0) == 0x6972 and
    8 of them
}