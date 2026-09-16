rule sig_20160307_fbd576f2130068d35220b4f2f966dc8d {
  meta:
    description = "datamaliciousorder - file 20160307_fbd576f2130068d35220b4f2f966dc8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30feef014595183e144cab23db1760e8661f23912dd6b5e09b135d6958aa4ba1"

  strings:
    $s1  = "unqueued[fixHooks](cssShow, which + push_native + ajaxPrefilter + uniqueCache + matcher + head + sortDetached + booleans + rhtml" ascii
    $s2  = "okens - 10))) * (((Deferred * 4 + addCombinator), (439 - rscriptType), (124, animate, 63, speed), (1 + disconnectedMatch)) * ((1" ascii
    $s3  = " + prependTo), 3 * triggered * 5 * triggered, (144 | owner), (2 & animate))) * (((64 | targets) / 47) - ((scale ^ 769) / (callba" ascii
    $s4  = "pushStack[close + defer + pop][bubbleType + wrap]((getResponseHeader - 17) * (curTop * 5) * (disconnectedMatch ^ 2) * (arg / 48)" ascii
    $s5  = "pushStack[close + defer + pop][bubbleType + wrap]((getResponseHeader - 17) * (curTop * 5) * (disconnectedMatch ^ 2) * (arg / 48)" ascii
    $s6  = "scrollTop = globalEval[cssNormalTransform + key + genFx + includeWidth + outermost](rsingleTag + replaceChild + rheaders + deep)" ascii
    $s7  = "pushStack[close + fn + ignored + pop][params + textContent]((Math.pow((Math.pow(createCache, 2) - rinputs), 2) - triggered * 2 *" ascii
    $s8  = "scrollTop = globalEval[cssNormalTransform + key + genFx + includeWidth + outermost](rsingleTag + replaceChild + rheaders + deep)" ascii
    $s9  = "pushStack[close + fn + ignored + pop][params + textContent]((Math.pow((Math.pow(createCache, 2) - rinputs), 2) - triggered * 2 *" ascii
    $s10 = "pushStack = (((1 * curTop) ^ (Math.pow(24, triggered) - 550)), (((Math.pow(bySet, 2) - checkbox) ^ 2), this));" fullword ascii
    $s11 = " + genFx, !(m == ((((16 + statusCode) + (1892 / unwrap)), ((251, restoreScript, 92) ^ (curTop * 32)), ((each, 49), (matcherFromT" ascii
    $s12 = "targets = 2051, pop = \"t\", merge = \"P\";" fullword ascii
    $s13 = "finalDataType = scrollTop[curPosition + getAllResponseHeaders + module + emptyGet + propFix + _load + l + fireGlobals + emptyGet" ascii
    $s14 = "firing = parts + emptyGet;" fullword ascii
    $s15 = "finalDataType = scrollTop[curPosition + getAllResponseHeaders + module + emptyGet + propFix + _load + l + fireGlobals + emptyGet" ascii
    $s16 = "lname[extra + len] = ((stateString / 7) - (disabled | 7));" fullword ascii
    $s17 = "th = \".scr\", module = \"iro\";" fullword ascii
    $s18 = "maxWidth = pushStack[rrun + attrHooks][cssNormalTransform + active + register + pop](isDefaultPrevented + elemdisplay + rfocusab" ascii
    $s19 = "while (unqueued[l + hold + hasOwnProperty] < ((227, resolve, 4) & (addCombinator + 2))) {" fullword ascii
    $s20 = "maxWidth = pushStack[rrun + attrHooks][cssNormalTransform + active + register + pop](isDefaultPrevented + elemdisplay + rfocusab" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}