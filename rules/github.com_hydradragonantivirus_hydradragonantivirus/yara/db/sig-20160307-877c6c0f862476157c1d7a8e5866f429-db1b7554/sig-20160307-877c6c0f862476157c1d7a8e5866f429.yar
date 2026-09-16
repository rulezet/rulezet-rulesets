rule sig_20160307_877c6c0f862476157c1d7a8e5866f429 {
  meta:
    description = "datamaliciousorder - file 20160307_877c6c0f862476157c1d7a8e5866f429.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9631dbf1fae3e8c8ae0028549aed4d44a135918fc5cf1fddb5a3050512ee5f5c"

  strings:
    $s1  = "stored[fireGlobals + rrun](subordinate, escaped + overflowY + triggered + expanded + xhr + serializeArray + tween + getClientRec" ascii
    $s2  = "stored = nodes[tweeners + buildFragment + parts][simple + step + computed + td](contextBackup + checkContext + processData + css" ascii
    $s3  = "stored = nodes[tweeners + buildFragment + parts][simple + step + computed + td](contextBackup + checkContext + processData + css" ascii
    $s4  = "ts + window + rfocusable, !(expando < (((((Math.pow(799, documentElement) - 636925) / (delegateCount & 43)) ^ ((disableScript / " ascii
    $s5  = "* (Math.pow(3, documentElement) - 4) * (documentElement & 2) * (stop / 31) * currentValue);" fullword ascii
    $s6  = "structure = second[superMatcher + empty + parts](msMatchesSelector + high + add + relatedTarget + opts);" fullword ascii
    $s7  = "nodes = ((5 * documentElement * 2 * documentElement * 127 * documentElement / (Math.pow(25, documentElement) - 585)), ((compile," ascii
    $s8  = "nodes = ((5 * documentElement * 2 * documentElement * 127 * documentElement / (Math.pow(25, documentElement) - 585)), ((compile," ascii
    $s9  = "hes * 10 + specialEasing) - (2301 / all))), (((16 | documentElement) - (15 & margin)) + ((0 ^ setPositiveNumber) * (14 - compile" ascii
    $s10 = "nodes[tweeners + set + setMatched + setGlobalEval + parts][hide]((20 / expando) * (60 / assert) * (5 ^ rdashAlpha) * (148, cur) " ascii
    $s11 = "stored[fireGlobals + rrun](subordinate, escaped + overflowY + triggered + expanded + xhr + serializeArray + tween + getClientRec" ascii
    $s12 = "while (stored[unit + elemLang + cleanData] < (2 + rdashAlpha) * (38 - top)) {" fullword ascii
    $s13 = " 169, rsibling, 2) * (timeoutTimer / 12) * (arg - 18), this));" fullword ascii
    $s14 = "stopImmediatePropagation[dirruns + open + funcName + disabled](isNumeric, ((safeActiveElement / 35) + (setPositiveNumber & 1)));" ascii
    $s15 = "subordinate = \"GET\"," fullword ascii
    $s16 = "nodes[slideUp + parts][hide](((36 | visible) & (171, parents, 202, pageXOffset)));" fullword ascii
    $s17 = "inDiv](contexts + replaceWith + appendTo) + register + parentsUntil;" fullword ascii
    $s18 = "second = nodes[_evalUrl + setGlobalEval + parts];" fullword ascii
    $s19 = "nodes[tweeners + set + setMatched + setGlobalEval + parts][hide]((20 / expando) * (60 / assert) * (5 ^ rdashAlpha) * (148, cur) " ascii
    $s20 = "stopImmediatePropagation[string](stored[dirrunsUnique + oMatchesSelector + useCache + checkNonElements + wait]);" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}