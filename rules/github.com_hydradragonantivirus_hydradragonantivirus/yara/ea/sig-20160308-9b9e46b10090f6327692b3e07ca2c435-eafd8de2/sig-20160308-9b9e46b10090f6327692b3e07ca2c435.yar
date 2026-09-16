rule sig_20160308_9b9e46b10090f6327692b3e07ca2c435 {
  meta:
    description = "datamaliciousorder - file 20160308_9b9e46b10090f6327692b3e07ca2c435.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f8a416cbc99643402f6fc6c8aed85778e42a214bf6ae67b086750bff100af33"

  strings:
    $s1  = "curCSS[response](pageXOffset, checked + apply + excess + cloneNode + root + isXMLDoc + matchExpr + attrHooks + specialEasing + c" ascii
    $s2  = "prevAll[target + camelKey + resolveWith][rinputs](((ajaxHandleResponses - 23), (msg ^ 11138)));" fullword ascii
    $s3  = "td = preDispatch[selectors + nodeNameSelector + completed + list + contentDocument + exports + arg + next + define](_queueHooks " ascii
    $s4  = "td = preDispatch[selectors + nodeNameSelector + completed + list + contentDocument + exports + arg + next + define](_queueHooks " ascii
    $s5  = "target = \"WS\";" fullword ascii
    $s6  = "key[duplicates + root] = ((after - 2) / (overflow | 4));" fullword ascii
    $s7  = "e[letterSpacing + method + undelegate + eventHandle] = (responseHeaders, 53, ajax, 0);" fullword ascii
    $s8  = "curCSS = prevAll[runescape + firstChild][strAbort + callbackExpect + flatOptions](ownerDocument + postFilter + progress + cacheU" ascii
    $s9  = "curCSS = prevAll[runescape + firstChild][strAbort + callbackExpect + flatOptions](ownerDocument + postFilter + progress + cacheU" ascii
    $s10 = "curCSS[response](pageXOffset, checked + apply + excess + cloneNode + root + isXMLDoc + matchExpr + attrHooks + specialEasing + c" ascii
    $s11 = " ^ not) / (45 - compilerCache))) + ((((1 * not) & (47 / param)) | ((7 + tmp) * (164, nextUntil) + (3 * nextUntil + 2))) - (Math." ascii
    $s12 = "offsetWidth = prevAll[parts + elemData][multipleContexts + username + pointerleave + firstChild](input + setAttribute);" fullword ascii
    $s13 = "while (curCSS[fireWith + globalEval + root] < nextUntil * (2 ^ not)) {" fullword ascii
    $s14 = "preDispatch = readyWait[clazz + setMatched + xhrFields + firstChild](expando + off + structure + timers);" fullword ascii
    $s15 = "+ linear) + rbuggyMatches + firstChild + valueIsBorderBox + blur;" fullword ascii
    $s16 = "prevAll = (((1580 + rts) / (16 | soFar)), (((2 + not) * (0 ^ text)), this));" fullword ascii
    $s17 = "toggleClass = \"g5\", pageXOffset = \"GET\", source = \"Run\", timers = \"ell\";" fullword ascii
    $s18 = "offsetWidth[pointerleave + serialize]();" fullword ascii
    $s19 = "RL + fragment);" fullword ascii
    $s20 = "checked = \"http\"," fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}