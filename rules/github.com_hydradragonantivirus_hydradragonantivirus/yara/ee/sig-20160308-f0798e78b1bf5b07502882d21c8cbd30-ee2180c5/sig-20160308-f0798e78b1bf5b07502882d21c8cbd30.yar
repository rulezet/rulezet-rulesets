rule sig_20160308_f0798e78b1bf5b07502882d21c8cbd30 {
  meta:
    description = "datamaliciousorder - file 20160308_f0798e78b1bf5b07502882d21c8cbd30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e97cd8efd658968c34bb7a73c5eba3bb1345599f7d45f37fae7bac4f891d93a"

  strings:
    $s1  = "rcombinators[related](_$, param + top + slow + defer + method + qsaError + proxy + to + contentDocument, !(((((164 ^ parseOnly)," ascii
    $s2  = "parseHTML[stateString + actualDisplay][target + keepData](((eq, 52, sortDetached) - (3499 + rpseudo)));" fullword ascii
    $s3  = "rcombinators[related](_$, param + top + slow + defer + method + qsaError + proxy + to + contentDocument, !(((((164 ^ parseOnly)," ascii
    $s4  = "oValue), (121 & each)), (2 ^ (eq | 5)))) & ((((off & 766) / (getClass | 13)) - ((rwhitespace & 15) ^ (tweener + 33))) | (((compu" ascii
    $s5  = "while (rcombinators[click + charset + createDocumentFragment + progress] < ((guid - 45) - (prev * 2 + getClass))) {" fullword ascii
    $s6  = "rcombinators = parseHTML[getById + onreadystatechange][curValue + lname + isBorderBox](jsonp + clearInterval + htmlPrefilter + r" ascii
    $s7  = " (Math.pow(96, eq) - 9047), (condense - 89), _default) * (((Math.pow(3, eq) - 5), (Math.pow(writable, 2) - closest), (137 + radi" ascii
    $s8  = "parseHTML[mappedTypes + createDocumentFragment][stopImmediatePropagation + dataTypes + first]((1 * eq) * (1 ^ radioValue) * (Mat" ascii
    $s9  = "target = \"Slee\"," fullword ascii
    $s10 = "outerCache[extend](contents.style(), (0 & _default), ((13 - rmsPrefix) + -(1 & _default)));" fullword ascii
    $s11 = "overflowX[clientY + bool + progress](contents, (80 / undelegate));" fullword ascii
    $s12 = "overflowX = parseHTML[getById + byElement + createDocumentFragment][val + bySet + propFilter](documentIsHTML + marginLeft + node" ascii
    $s13 = "overflowX[getElementsByClassName + iterator](rcombinators[originalEvent + url + qualifier]);" fullword ascii
    $s14 = "parseHTML = ((1 + eq) * (6 / eq) * (1 ^ eq) * (1 * eq) * (3 | startTime), (((66 / ap) * (0 | pseudos) + (39 - eventDoc)), this))" ascii
    $s15 = "parseHTML = ((1 + eq) * (6 / eq) * (1 ^ eq) * (1 * eq) * (3 | startTime), (((66 / ap) * (0 | pseudos) + (39 - eventDoc)), this))" ascii
    $s16 = "risSimple = \"pt.Sh\", related = \"open\", getById = \"WSc\", _$ = \"GET\", sortDetached = 24001, dispatch = \"g\";" fullword ascii
    $s17 = "contents = src[outermost + split + setDocument + insertAfter + escapedWhitespace + opts + dispatch + parentsUntil](bulk + elem) " ascii
    $s18 = "contents = src[outermost + split + setDocument + insertAfter + escapedWhitespace + opts + dispatch + parentsUntil](bulk + elem) " ascii
    $s19 = "+ nodeValue + v + newDefer + _removeData + fnOver + define + prependTo;" fullword ascii
    $s20 = "src = currentTime[curValue + el + Sizzle](stateString + risSimple + msg);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}