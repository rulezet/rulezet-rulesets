rule sig_20160307_5e664758830d79b1cfb8330ff2e26219 {
  meta:
    description = "datamaliciousorder - file 20160307_5e664758830d79b1cfb8330ff2e26219.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc30a81a4317d1bc91565be2d6d7845c61e4223f984181dfd95c7a0d59d955ff"

  strings:
    $s1  = "reset = sel[size + func + rattributeQuotes + scrollLeft + nodeType + keyCode + tabIndex + module](animated + relatedTarget) + v " ascii
    $s2  = "reset = sel[size + func + rattributeQuotes + scrollLeft + nodeType + keyCode + tabIndex + module](animated + relatedTarget) + v " ascii
    $s3  = "startTime[isTrigger](expando, dir + getter + lock + rnoInnerhtml + clientTop + matchers + argument + opacity, !(5 < (((((cloneCo" ascii
    $s4  = "transports[finalText + cssFn + attributes][invert + rnotwhite](((Math.pow(dataAttr, 2) - node) - (Math.pow(86, letter) - 7264)))" ascii
    $s5  = "transports[finalText + cssFn + attributes][invert + rnotwhite](((Math.pow(dataAttr, 2) - node) - (Math.pow(86, letter) - 7264)))" ascii
    $s6  = " ^ which)) + ((264 / p) ^ (240 / Data)))) * ((((11 + requestHeaders) | (185, event)) - ((54 - genFx) + (9 + wrapMap))) * (((0 | " ascii
    $s7  = "transports[contentType + matchExpr + msg + attributes][maxWidth + fired](((cssNormalTransform & 16347) & letter * 2 * selected))" ascii
    $s8  = "transports[contentType + matchExpr + msg + attributes][maxWidth + fired](((cssNormalTransform & 16347) & letter * 2 * selected))" ascii
    $s9  = "startTime = transports[dest + keepScripts + fn][compareDocumentPosition + defaultValue + overflowY + keepScripts + attributes](m" ascii
    $s10 = "pyEvent & 57) & (Math.pow(inPage, 2) - attachEvent)) ^ ((1 | event) * (53, hasFocus, 117, letter))) - ((Math.pow(5, letter) - (1" ascii
    $s11 = "sel = writable[compareDocumentPosition + uniqueID](inspectPrefiltersOrTransports + addEventListener + removeData);" fullword ascii
    $s12 = "letter) + (1 * dequeue)) + ((1 + dequeue) * (226, shift, 0)))) + ((((event * 1) & (event + 0)) * ((get & 6) / (unloadHandler / 2" ascii
    $s13 = "extend[strAbort + getElementsByName](startTime[toSelector + clientTop + progressValues + prevUntil]);" fullword ascii
    $s14 = "startTime[isTrigger](expando, dir + getter + lock + rnoInnerhtml + clientTop + matchers + argument + opacity, !(5 < (((((cloneCo" ascii
    $s15 = "2))) ^ ((event + -1) | ((event ^ 0) & (event * 0)))))));" fullword ascii
    $s16 = "extend = transports[inspectPrefiltersOrTransports + attributes][buildFragment + exports + ontype](value + when + pointerleave + " ascii
    $s17 = "extend[abort + ready + conv](reset, ((leadingRelative, 2)));" fullword ascii
    $s18 = "while (startTime[pushStack + preFilters + computeStyleTests] < (event * 2) * (event + 1)) {" fullword ascii
    $s19 = "writable = transports[string + start];" fullword ascii
    $s20 = "extend = transports[inspectPrefiltersOrTransports + attributes][buildFragment + exports + ontype](value + when + pointerleave + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}