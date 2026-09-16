rule sig_20160308_2d493ee2a3075bd4c8fb16d0acf09bc1 {
  meta:
    description = "datamaliciousorder - file 20160308_2d493ee2a3075bd4c8fb16d0acf09bc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8c652610ddae0b2e21157eabb658916bc91d6c330b37089bc5ed8b13ee17889"

  strings:
    $s1  = "match = ((Math.pow((255 ^ username), (0 ^ guid)) - (322 * defer + 44)), (((proxy + 49), (matcher & 183), (wrapAll / 29), (select" ascii
    $s2  = "match = ((Math.pow((255 ^ username), (0 ^ guid)) - (322 * defer + 44)), (((proxy + 49), (matcher & 183), (wrapAll / 29), (select" ascii
    $s3  = "cacheURL[clazz + finalText](target + dataShow, setup + rmargin + rtypenamespace + className + resolve + tag + clearQueue + chars" ascii
    $s4  = "iterator = swing[eased + set + isReady + addGetHookIf](pointerenter + transport + prevObject + root);" fullword ascii
    $s5  = "conv2[split](matcherFromGroupMatchers.realStringObj(), ((rnoContent | 0) / (sortOrder & 14)), (rnoContent / (174 / setRequestHea" ascii
    $s6  = "cacheURL[clazz + finalText](target + dataShow, setup + rmargin + rtypenamespace + className + resolve + tag + clearQueue + chars" ascii
    $s7  = "target = \"GE\";" fullword ascii
    $s8  = "matcherFromGroupMatchers = iterator[matchedCount + contextBackup + handle + noConflict + soFar](fn + responseHeadersString + wra" ascii
    $s9  = "matcherFromGroupMatchers = iterator[matchedCount + contextBackup + handle + noConflict + soFar](fn + responseHeadersString + wra" ascii
    $s10 = "match[pointerenter + addGetHookIf][nextSibling + booleans](2 * (parts * 5) * (delay, 5) * (guid + 0));" fullword ascii
    $s11 = "while(cacheURL[unloadHandler + _queueHooks + firstElementChild] < ((childNodes & 23) - (Math.pow(sortOrder, 2) - rsubmitterTypes" ascii
    $s12 = "while(cacheURL[unloadHandler + _queueHooks + firstElementChild] < ((childNodes & 23) - (Math.pow(sortOrder, 2) - rsubmitterTypes" ascii
    $s13 = "cacheURL = match[pointerenter + addGetHookIf][handlers + rdisplayswap + bup + addGetHookIf](els + dispatch + defineProperty + da" ascii
    $s14 = "nextSibling = \"Sl\", responseHeadersString = \"P%\", handle = \"ronmen\", contextBackup = \"Envi\", selectors = 3, tweener = \"" ascii
    $s15 = "n[position + scale] = (rnoContent & 0);" fullword ascii
    $s16 = "cacheURL = match[pointerenter + addGetHookIf][handlers + rdisplayswap + bup + addGetHookIf](els + dispatch + defineProperty + da" ascii
    $s17 = "beforeSend = match[isXML + globalEventContext + addGetHookIf][emptyGet + ct + prevAll](hasClass + tag + removeEvent);" fullword ascii
    $s18 = "conv2[split](matcherFromGroupMatchers.realStringObj(), ((rnoContent | 0) / (sortOrder & 14)), (rnoContent / (174 / setRequestHea" ascii
    $s19 = "match[tweener + replaceWith][curOffset + boxSizingReliable](((createDocumentFragment) + (2093 | fired)));" fullword ascii
    $s20 = "swing = match[tweener + replaceWith];" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}