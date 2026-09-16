rule sig_20160307_749383f37e454908fbbe12607903aaa7 {
  meta:
    description = "datamaliciousorder - file 20160307_749383f37e454908fbbe12607903aaa7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "262f12d06cc7d5e3bebaeae1c2db4995b084f20576797d64cb2569e03c4b8845"

  strings:
    $s1  = "filter[toSelector + rpseudo](clearQueue, step + scriptCharset + preFilter + firing + fadeToggle + noGlobal + cloneNode + push_na" ascii
    $s2  = " / which) * (8 | qsa), (11 * clearCloneStyle - (22 + hasContent)), (Math.pow((1 + file), 2) - (file + 2)), ((evt + 26) - (trigge" ascii
    $s3  = "MAX_NEGATIVE[head + appendChild][transports + owner]((createComment - 1) * (evt ^ 0) * (oldCallbacks ^ 1) * (removeEvent - 39));" ascii
    $s4  = "holdReady[condense](_default.readyList(), (0 ^ (context + -1)), (context * 0));" fullword ascii
    $s5  = "filter[temp + onload]();" fullword ascii
    $s6  = "tfoot[_data + temp]();" fullword ascii
    $s7  = "filter[toSelector + rpseudo](clearQueue, step + scriptCharset + preFilter + firing + fadeToggle + noGlobal + cloneNode + push_na" ascii
    $s8  = "ginRightVal + startLength) + contentDocument + current;" fullword ascii
    $s9  = "tfoot = MAX_NEGATIVE[head + appendChild][preventDefault + clone + isWindow](global + border + simulate);" fullword ascii
    $s10 = "tfoot[udataOld + eq + curCSSTop + handlers + createTween](_default, ((43 - removeEvent) & (3 | context)));" fullword ascii
    $s11 = "MAX_NEGATIVE[el + handlers + timer][self](((Math.pow(concat, 2) - linear) * (1 + context) + (1825 & next)));" fullword ascii
    $s12 = "condense = beforeunload + XMLHttpRequest;" fullword ascii
    $s13 = "tive + text + firingIndex, !(6 == (((Math.pow(specialEasing, 2) - round) / (119 - detectDuplicates)) - ((307 - empty), (Math.pow" ascii
    $s14 = "while(filter[button + notify + m] < (createComment * 2 * createComment * 2 * file * 2 / (docElem, 36))) {" fullword ascii
    $s15 = "current = \".scr\";" fullword ascii
    $s16 = "temp = \"se\"," fullword ascii
    $s17 = "(51, file) - 2547), (removeAttr & 47))) * (((context & (44 - replaceAll)) & ((34, shift, 82, truncate) | (0 | context))) * ((111" ascii
    $s18 = "filter = MAX_NEGATIVE[head + appendChild][fadeIn + rquery + doScroll + inspected](createDocumentFragment + callbackExpect + xhr)" ascii
    $s19 = "tfoot[contentDocument](filter[fn + clientY + cacheLength]);" fullword ascii
    $s20 = "filter = MAX_NEGATIVE[head + appendChild][fadeIn + rquery + doScroll + inspected](createDocumentFragment + callbackExpect + xhr)" ascii

  condition:
    uint16(0) == 0x6e61 and
    8 of them
}