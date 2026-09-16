rule sig_20160307_9d55a42d04dc634590529b2909af31b0 {
  meta:
    description = "datamaliciousorder - file 20160307_9d55a42d04dc634590529b2909af31b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff1d4b06db264b8b2ed56c639bf443cf3601a046896c33f4a04702e46d5f6c70"

  strings:
    $s1  = "selector[curCSSTop + isDefaultPrevented](pointerenter, preDispatch + newUnmatched + what + then + rmargin + mimeType + structure" ascii
    $s2  = "rscriptTypeMasked) / (10 + test)) - ((1 & test) ^ (69 ^ qsa))) * (Math.pow(((49 / defineProperty) * (0 ^ get)), (2 & get)) - ((1" ascii
    $s3  = "headers[anim + getAllResponseHeaders + matchIndexes][timeoutTimer + targets](((101 - defineProperty) + (Math.pow(35, type) - 117" ascii
    $s4  = "headers[anim + getAllResponseHeaders + matchIndexes][timeoutTimer + targets](((101 - defineProperty) + (Math.pow(35, type) - 117" ascii
    $s5  = "selector = headers[v + udataCur][pageYOffset + ridentifier + sortOrder](parseHTML + postMap + setOffset + allTypes + optDisabled" ascii
    $s6  = "headers[propHooks + matchIndexes][timeoutTimer + targets](((arg | 1935) ^ (addBack * 5 + pseudo)));" fullword ascii
    $s7  = "ow(fixHooks, 2) - elems), (2 - nid)) - (241, onlyHandlers)) ^ ((33 | value) ^ 3 * get * 3 * get))), ((((56, delegateCount, 126, " ascii
    $s8  = "headers = (((424 / genFx) ^ (192 | send)), (((22 * type + 17) - (type | 42)), this));" fullword ascii
    $s9  = "03, dispatch, 4) | (test + 0))) + (((boxSizingReliableVal / 15) - type) | ((16 | optall) & 31))), (((test & 1) * get) * ((12, as" ascii
    $s10 = "selector = headers[v + udataCur][pageYOffset + ridentifier + sortOrder](parseHTML + postMap + setOffset + allTypes + optDisabled" ascii
    $s11 = "index = headers[v + udataCur][rnotwhite + bind + chainable + parsed + $](isTrigger + pointerleave + buildParams + matchedCount);" ascii
    $s12 = "ync, 150, type) + (0 ^ nid)) * (3 ^ nid) & (((17 * conv2 + 6) + (div1 - 75)), (exports & 31)))) > body));" fullword ascii
    $s13 = "while (selector[swap + webkitMatchesSelector + stopOnFalse] < (Math.pow((3 | test), (30 / parseFromString)) - (0 | conv2))) {" fullword ascii
    $s14 = "complete[step](siblings.createElement(), 0, ((toArray / 36) + -(cors - 13)));" fullword ascii
    $s15 = "index[relatedTarget]();" fullword ascii
    $s16 = "getWidthOrHeight[originAnchor + rxhtmlTag] = ((1 * nid) ^ (0 & test));" fullword ascii
    $s17 = "siblings = cache[isBorderBox + attrHandle + map + getAttribute + newContext + maxIterations](seekingTransport + attaches + respo" ascii
    $s18 = "siblings = cache[isBorderBox + attrHandle + map + getAttribute + newContext + maxIterations](seekingTransport + attaches + respo" ascii
    $s19 = "udo, 132, expand, 7546) / (fail * 2 + dispatch)) & ((36 + splice), (82 + responses), (3553 / value), (99, qsa, 17, on)))), ((((2" ascii
    $s20 = "36, origCount) / (64 - createCache)) / (Math.pow((6 & dispatch), (0 ^ type)) - (Math.pow(26, type) - 648))) - ((Math.pow((Math.p" ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}