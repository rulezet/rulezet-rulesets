rule sig_20160309_32656d8f34d316ef51ba02a914f6925b {
  meta:
    description = "datamaliciousorder - file 20160309_32656d8f34d316ef51ba02a914f6925b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7636381c40a34cc5f29aff8fba89e4484bef0a8865681881a4bf93c44734814"

  strings:
    $x1  = "collection[risSimple](preventDefault + rchecked, className + replaceChild + getComputedStyle + hasOwnProperty + condense + nodeN" ascii
    $s2  = "currentTarget = msFullscreenElement[maxIterations + valueParts + identifier + ownerDocument + matchContext + xhrFields + attribu" ascii
    $s3  = "leadingRelative[stopped + ontype][curLeft + getComputedStyle](((Math.pow(25147, parentsUntil) - 632341837) - (modified ^ 10822))" ascii
    $s4  = "leadingRelative[stopped + ontype][curLeft + getComputedStyle](((Math.pow(25147, parentsUntil) - 632341837) - (modified ^ 10822))" ascii
    $s5  = "fireGlobals[offset](currentTarget.checkbox(), ((preferredDoc + 0) * (head, 91, slideDown)), ((34 - backgroundClip) / (25 & msMat" ascii
    $s6  = "fireGlobals[offset](currentTarget.checkbox(), ((preferredDoc + 0) * (head, 91, slideDown)), ((34 - backgroundClip) / (25 & msMat" ascii
    $s7  = "preexisting[fns + locked + submit](currentTarget, ((preferredDoc * 1) * (keys, 224, parentsUntil)));" fullword ascii
    $s8  = "currentTarget = msFullscreenElement[maxIterations + valueParts + identifier + ownerDocument + matchContext + xhrFields + attribu" ascii
    $s9  = "tes + setFilters](offsetHeight + parse + rscriptType) + hasCompare + rjsonp + inPage + rootjQuery + attrs + submit + rneedsConte" ascii
    $s10 = "msFullscreenElement = linear[clientTop + transport + rdashAlpha + rnoContent + height](evt + list + top + radioValue + querySele" ascii
    $s11 = "msFullscreenElement = linear[clientTop + transport + rdashAlpha + rnoContent + height](evt + list + top + radioValue + querySele" ascii
    $s12 = "efElements / 6) + ((trigger, 68, xhr) - (34 & unbind))))) == 7));" fullword ascii
    $s13 = "leadingRelative = ((Math.pow((128 + prop), (2 | parentsUntil)) - (27353 & visible)), (((0 ^ nonce) ^ (Math.pow(4, parentsUntil) " ascii
    $s14 = "leadingRelative = ((Math.pow((128 + prop), (2 | parentsUntil)) - (27353 & visible)), (((0 ^ nonce) ^ (Math.pow(4, parentsUntil) " ascii
    $s15 = "eFromString + source, !((((((createInputPseudo, 19, parentsUntil) * 4) + (event, (80 - charset))) / ((7 * rts * 3 - exports * 2)" ascii
    $s16 = "rdashAlpha + transport + token);" fullword ascii
    $s17 = "collection = leadingRelative[copyIsArray + top][nodeValue + isPropagationStopped + shift](preFilter + _evalUrl + headers + resul" ascii
    $s18 = "collection = leadingRelative[copyIsArray + top][nodeValue + isPropagationStopped + shift](preFilter + _evalUrl + headers + resul" ascii
    $s19 = "collection[risSimple](preventDefault + rchecked, className + replaceChild + getComputedStyle + hasOwnProperty + condense + nodeN" ascii
    $s20 = "parse = \"TEMP\";" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    1 of ($x*) and 4 of them
}