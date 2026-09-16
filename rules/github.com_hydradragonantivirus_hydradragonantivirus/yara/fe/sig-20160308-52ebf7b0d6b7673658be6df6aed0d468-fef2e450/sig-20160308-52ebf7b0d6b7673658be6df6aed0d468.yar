rule sig_20160308_52ebf7b0d6b7673658be6df6aed0d468 {
  meta:
    description = "datamaliciousorder - file 20160308_52ebf7b0d6b7673658be6df6aed0d468.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9600ad6fcfd9f2a07c197efe1a71cd5b6fbe80e3c98b16b217f371403c74d0ac"

  strings:
    $s1  = "grep[rtypenamespace + cached](left, qsa + tr + container + copyIsArray + addGetHookIf + eventDoc + cssPrefixes + push_native + a" ascii
    $s2  = "nim + anim, !((((Math.pow(((key) * (255, mimeType, 247, handleObj) + 5), ((animate / 33), (Math.pow(urlAnchor, 2) - srcElements)" ascii
    $s3  = "ld * 3))) ^ ((((lastChild | 1) | lastChild) + ((0 & fast) | 0)) * (((optgroup & 8) - (checkClone - 0)) | ((fast & 1) ^ (username" ascii
    $s4  = "jqXHR = visibility[elemdisplay + bind + rkeyEvent + contexts + pipe + contains + cached + image](matchesSelector + msMatchesSele" ascii
    $s5  = "jqXHR = visibility[elemdisplay + bind + rkeyEvent + contexts + pipe + contains + cached + image](matchesSelector + msMatchesSele" ascii
    $s6  = "to[promise + temp] = lastChild;" fullword ascii
    $s7  = "hasOwn[size + body][ajaxPrefilter + ontype](((4531 / attachEvent) - (32 | matcherIn)));" fullword ascii
    $s8  = ", (16 | prevAll), (1 * hold))) - (315 * (parentNode | 4) + rquery * 2)), (((pageXOffset ^ 17)) * (fast * (2 ^ lastChild)) + (Mat" ascii
    $s9  = "memory = \".scr\";" fullword ascii
    $s10 = "temp = \"ion\"," fullword ascii
    $s11 = "removeEvent = hasOwn[globalEval + siblings][triggerHandler + identifier + removeAttribute + Symbol](map + MAX_NEGATIVE + aup + p" ascii
    $s12 = "ctor + dataFilter) + configurable + memory;" fullword ascii
    $s13 = "removeEvent = hasOwn[globalEval + siblings][triggerHandler + identifier + removeAttribute + Symbol](map + MAX_NEGATIVE + aup + p" ascii
    $s14 = "removeEvent[activeElement + origType + identifier]();" fullword ascii
    $s15 = "removeEvent[window + unshift + match + identifier](jqXHR, ((0 | hold) ^ 0));" fullword ascii
    $s16 = "hasOwn = (((204 & offsetHeight) / 1), ((Math.pow((Math.pow(insertAfter, 2) - rquery), 2) - (createCache - 118)), this));" fullword ascii
    $s17 = "grep = hasOwn[status + Data + body][triggerHandler + identifier + removeAttribute + camelCase + classNames](JSON + setOffset + u" ascii
    $s18 = "globalEval = \"WSc\", pipe = \"entS\";" fullword ascii
    $s19 = "grep[rtypenamespace + cached](left, qsa + tr + container + copyIsArray + addGetHookIf + eventDoc + cssPrefixes + push_native + a" ascii
    $s20 = "left = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}