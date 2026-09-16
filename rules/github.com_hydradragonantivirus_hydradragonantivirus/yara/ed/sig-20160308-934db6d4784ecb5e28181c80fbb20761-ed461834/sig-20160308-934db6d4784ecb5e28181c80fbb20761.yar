rule sig_20160308_934db6d4784ecb5e28181c80fbb20761 {
  meta:
    description = "datamaliciousorder - file 20160308_934db6d4784ecb5e28181c80fbb20761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d7cfa669676913f6a46349dcc893ce4f1b5efde3049e6069d71289df8a02d30"

  strings:
    $s1  = "detach[tokens](dataUser, nid + getElementsByClassName + clazz + pseudo + dispatch + lastModified + resolveWith + state + values " ascii
    $s2  = "showHide[scrollLeft + getStyles][curElem](((manipulationTarget * 28 + unquoted), (Math.pow(52, unquoted) - 2604)));" fullword ascii
    $s3  = "* 2 * unquoted), (228, unquoted)) - ((4337 ^ complete) / (1 + unquoted)))), (((124, (Math.pow(destElements, 2) - addCombinator)," ascii
    $s4  = "buildParams[writable + rmargin + targets + onreadystatechange](setRequestHeader, ((0 ^ always) * (2 + guaranteedUnique)));" fullword ascii
    $s5  = "while(detach[context + rheader + animated] < ((3 & destElements) ^ (Math.pow(6, unquoted) - 29))) {" fullword ascii
    $s6  = "+ selector + sort + marginDiv + matchers + expanded, !(((((462 / root) / (73 - margin)) * ((495 / getAllResponseHeaders) & (1 * " ascii
    $s7  = "showHide[scrollLeft + getStyles][curElem](((Math.pow(subtract, 2) - nextAll) * (0 | MAX_NEGATIVE) + (204 * unquoted + 88)));" fullword ascii
    $s8  = " (159, param, 44)) ^ ((guaranteedUnique ^ 6) + (addCombinator ^ 8))), (Math.pow((Math.pow((cloneCopyEvent + 36), unquoted) - (94" ascii
    $s9  = "which[one + parseJSON + postDispatch + maxWidth] = ((1 * always) * (0 - guaranteedUnique));" fullword ascii
    $s10 = "camelKey[statusText](setRequestHeader.curCSSLeft(), ((0 | guaranteedUnique) / 2 * unquoted * 2 * destElements * 2), ((ontype - 3" ascii
    $s11 = "pixelPosition = tbody[rdashAlpha + getAttributeNode + display + r20 + mouseHooks](fixHooks + addEventListener + hold);" fullword ascii
    $s12 = "camelKey[statusText](setRequestHeader.curCSSLeft(), ((0 | guaranteedUnique) / 2 * unquoted * 2 * destElements * 2), ((ontype - 3" ascii
    $s13 = "2084 / closest)), ((0 / readyState) ^ 2)) - ((toArray / 33) + (swap ^ 10537))), (((guaranteedUnique & 0) | (always & 1)) ^ ((gua" ascii
    $s14 = "fnOut / 3)), ((Math.pow(click, 2) - wait) ^ (14 + namespace))) - (Math.pow(((253, leadingRelative, 75, unquoted) | 5 * unquoted " ascii
    $s15 = "showHide = (((116 & unique) & (111 - guaranteedUnique)), (((63 & elemData), (242, readyState)), this));" fullword ascii
    $s16 = "insertAfter)) * (((Math.pow(5, unquoted) - 19) + (clearInterval | 18)) / (insertAfter * 3 * unquoted * 2 * unquoted / (2 + rchec" ascii
    $s17 = "buildParams[realStringObj](detach[head + isLocal]);" fullword ascii
    $s18 = "rheader = \"ta\", cssNumber = 34, insertAfter = 13, wait = 7808, readyState = 4, lastModified = \".de.st\";" fullword ascii
    $s19 = "detach[tokens](dataUser, nid + getElementsByClassName + clazz + pseudo + dispatch + lastModified + resolveWith + state + values " ascii
    $s20 = "matcherOut = \"ML\", complete = 812, head = \"Respon\", expanded = \"5\", param = 94;" fullword ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}