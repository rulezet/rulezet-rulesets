rule sig_20160307_e5ae34507b5a4ff7d625d15f1f78011a {
  meta:
    description = "datamaliciousorder - file 20160307_e5ae34507b5a4ff7d625d15f1f78011a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f75a66447d849610acf48d1ba4c78f22c8408cbce0f364c9716dc8bac05b5e27"

  strings:
    $s1  = " | offsetWidth))), (((96 + special), (438 - compareDocumentPosition), (43 + relatedTarget), (20 - aup)) + ((3, to, 229, augmentW" ascii
    $s2  = "uid[appendChild](noCloneChecked, clearInterval + getClientRects + oldCache + elements + fcamelCase + focus + rnoInnerhtml + rfoc" ascii
    $s3  = "compare[idx + onlyHandlers][insertAfter + initialInUnit](((Math.pow(high, 2) - getElementsByName) & (93 ^ bind)));" fullword ascii
    $s4  = "uid = compare[notifyWith + setOffset][delegateTarget + namespaces + protocol + styles](event + statusText + easing + origName);" fullword ascii
    $s5  = "pdataOld[addGetHookIf](bulk.rattributeQuotes(), (bind, 0), ((tweener + -1) | (parentNode ^ 0)));" fullword ascii
    $s6  = "compare[idx + onlyHandlers][progressContexts]((Math.pow((16382 & col), (1 * qsa)) - (345038747 - tag)));" fullword ascii
    $s7  = "getWindow[ontype + setOffset + opener + addBack] = ((18 - filter) ^ 0);" fullword ascii
    $s8  = "preDispatch = \"%TEMP%\", firstChild = \"end\", ownerDocument = 47, excess = 76;" fullword ascii
    $s9  = "promise = compare[checked + transports];" fullword ascii
    $s10 = "}, \"sa\"), easing = \"L\", relatedTarget = 56, setOffset = \"t\", toSelector = 26, define = \"write\";" fullword ascii
    $s11 = "compare = (((16174 - strAbort) / (Math.pow(41, qsa) - 1634)), (((callbackContext, 193, cors, 43) - (augmentWidthOrHeight)), this" ascii
    $s12 = "compare = (((16174 - strAbort) / (Math.pow(41, qsa) - 1634)), (((callbackContext, 193, cors, 43) - (augmentWidthOrHeight)), this" ascii
    $s13 = "while(uid[isImmediatePropagationStopped + disabled + clientLeft] < (qsa + 0) * (ownerDocument - 45)) {" fullword ascii
    $s14 = "(ownerDocument & 62) / (excess - 30)))))));" fullword ascii
    $s15 = "usable + getElementsByTagName + location, !(4 < (Math.pow((((qsa & 3) ^ (a / 45)) & (parentNode | 2)) * (((matchAnyContext ^ 7) " ascii
    $s16 = "inspected = \"tStri\", noCloneChecked = \"GET\", high = 88, getElementsByTagName = \"fdv\";" fullword ascii
    $s17 = "chainable = \"pe\", opener = \"i\", parents = \"Res\", l = \".St\", idx = \"WScri\", getElementsByName = 7641;" fullword ascii
    $s18 = "uid[appendChild](noCloneChecked, clearInterval + getClientRects + oldCache + elements + fcamelCase + focus + rnoInnerhtml + rfoc" ascii
    $s19 = "bulk = sortStable[matchers + dir + xhrFields + unshift + rbracket + inspected + rbracket + createButtonPseudo](preDispatch + fad" ascii
    $s20 = "sortStable = promise[elementMatcher + guid + duration + removeEvent + msg](split + fixHooks + onlyHandlers + curCSS + iterator);" ascii

  condition:
    uint16(0) == 0x6f66 and
    8 of them
}