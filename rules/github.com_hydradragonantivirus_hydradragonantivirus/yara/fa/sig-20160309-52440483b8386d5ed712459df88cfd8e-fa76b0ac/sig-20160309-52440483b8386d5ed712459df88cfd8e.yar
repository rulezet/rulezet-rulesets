rule sig_20160309_52440483b8386d5ed712459df88cfd8e {
  meta:
    description = "datamaliciousorder - file 20160309_52440483b8386d5ed712459df88cfd8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956238af91e383e42994f2ff4930fb376d3b553afa08024aa4057f1329f902d3"

  strings:
    $s1  = "animation = teardown[rescape + genFx + rkeyEvent + dataPriv + pattern + keyHooks + proxy + pipe](compiled + status + progressCon" ascii
    $s2  = "XMLHttpRequest[div](pixelPosition, nType + removeEventListener + pseudo + compareDocumentPosition + disable + get + nativeStatus" ascii
    $s3  = "XMLHttpRequest[div](pixelPosition, nType + removeEventListener + pseudo + compareDocumentPosition + disable + get + nativeStatus" ascii
    $s4  = "animation = teardown[rescape + genFx + rkeyEvent + dataPriv + pattern + keyHooks + proxy + pipe](compiled + status + progressCon" ascii
    $s5  = "unique[when](animation.postDispatch(), toArray, (0 / (actualDisplay - 46)));" fullword ascii
    $s6  = "contents = rparentsprev[addEventListener + random + finalValue];" fullword ascii
    $s7  = "rparentsprev[namespaces + diff + checkDisplay][gotoEnd]((5 / camelKey) * (3 & fadeTo) * (1 * eq) * (Math.pow(4, eq) - 11) * dele" ascii
    $s8  = "XMLHttpRequest = rparentsprev[namespaces + cos + childNodes + lname][rhash + isPropagationStopped + lname](cssPrefixes + parseXM" ascii
    $s9  = "rparentsprev[namespaces + diff + checkDisplay][gotoEnd]((5 / camelKey) * (3 & fadeTo) * (1 * eq) * (Math.pow(4, eq) - 11) * dele" ascii
    $s10 = "teardown = contents[isHidden + radio + siblings](fnOver + fnOut + rquickExpr);" fullword ascii
    $s11 = "texts + method) + getClientRects + get + append + animate;" fullword ascii
    $s12 = "outermostContext = XMLHttpRequest[slideDown + fixHook + style + pageY];" fullword ascii
    $s13 = "pipe = \"ngs\"," fullword ascii
    $s14 = "style = \"od\", compareDocumentPosition = \"/myo\", selection = 115, first = \"MLHTTP\", pageY = \"y\";" fullword ascii
    $s15 = "parents = (function String.prototype.postDispatch() {" fullword ascii
    $s16 = "var submit = \"/logs\"," fullword ascii
    $s17 = "rparentsprev = (((160 / eq)), ((2 * eq * 7 * eq * 2 * eq / (658 / qualifier)), this));" fullword ascii
    $s18 = "L + until + first);" fullword ascii
    $s19 = "cssNumber[attr + preFilter] = ((selection), (0 ^ toArray));" fullword ascii
    $s20 = "uniqueSort[cos + selector]();" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}