rule sig_20160309_54e24bb9ee468c13173110b19479a3a4 {
  meta:
    description = "datamaliciousorder - file 20160309_54e24bb9ee468c13173110b19479a3a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a76c6e065db8c82b11c9a492a58a061e9041fdef6bf98d31735936aa1df90b5"

  strings:
    $s1  = "insertBefore[restoreScript + attrs + ajaxTransport][responseContainer + push]((ajaxSetup / 46) * (parts - 48) * (addHandle, 177," ascii
    $s2  = "overrideMimeType[uniqueCache + selector + inArray](copy + calculatePosition, pipe + childNodes + source + preFilters + compilerC" ascii
    $s3  = "relatedTarget = \"%TEMP%\";" fullword ascii
    $s4  = "insertBefore[restoreScript + attrs + ajaxTransport][responseContainer + push]((ajaxSetup / 46) * (parts - 48) * (addHandle, 177," ascii
    $s5  = "getClientRects[isDefaultPrevented](excess.inspected(), (38 - isTrigger), ((3 * compare + 2) - (val - 10)));" fullword ascii
    $s6  = "height = overrideMimeType[readyList + preMap + elementMatcher + props + seekingTransport];" fullword ascii
    $s7  = "pipe = \"http:\", dataFilter = \"rite\", ajaxTransport = \"t\", preFilters = \"ciny.r\";" fullword ascii
    $s8  = "excess = access[context + classes + createElement + binary + module](relatedTarget + input) + curCSSLeft + addGetHookIf + before" ascii
    $s9  = "excess = access[context + classes + createElement + binary + module](relatedTarget + input) + curCSSLeft + addGetHookIf + before" ascii
    $s10 = "insertBefore = ((15 + compare * 5), (((getAllResponseHeaders + 84) / (closest / 34)), this));" fullword ascii
    $s11 = " compare) * (2 + requestHeadersNames) * (113, timer, 5) * (simple, 71, high, 3) * compare * (4 + isEmptyObject));" fullword ascii
    $s12 = "overrideMimeType[uniqueCache + selector + inArray](copy + calculatePosition, pipe + childNodes + source + preFilters + compilerC" ascii
    $s13 = "overrideMimeType = insertBefore[elements + bulk][elemLang + related + body](e + next + sel + progressValues);" fullword ascii
    $s14 = "ache + tuple + returned + input + node + contexts + timeoutTimer + pushStack + initialInUnit, !(requestHeadersNames < ((((0 / eq" ascii
    $s15 = "addGetHookIf = \"ginalE\", removeAttribute = \"c\", guid = \"posit\", compare = 2;" fullword ascii
    $s16 = "siblingCheck[triggerHandler + noConflict](excess, ((1 + -isEmptyObject) ^ 2));" fullword ascii
    $s17 = "parents = insertBefore[bindType + responseContainer + disabled];" fullword ascii
    $s18 = ") / (12 & bup)) - (((59 & whitespace) ^ (0 & errorCallback)) - (7 * XMLHttpRequest & (83, defer)))) | ((((468 / origName), (129," ascii
    $s19 = "siblingCheck = insertBefore[rcomma + round][elemLang + preDispatch + size + stateString + fontWeight](activeElement + wrapMap + " ascii
    $s20 = "siblingCheck = insertBefore[rcomma + round][elemLang + preDispatch + size + stateString + fontWeight](activeElement + wrapMap + " ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}