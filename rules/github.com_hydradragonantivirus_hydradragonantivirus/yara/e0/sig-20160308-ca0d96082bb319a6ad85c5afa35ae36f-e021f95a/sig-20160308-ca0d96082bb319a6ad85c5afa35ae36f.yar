rule sig_20160308_ca0d96082bb319a6ad85c5afa35ae36f {
  meta:
    description = "datamaliciousorder - file 20160308_ca0d96082bb319a6ad85c5afa35ae36f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e14e0d18b2db8ca09fc0017a14209a4a2426c3cfc286bf87bb055ec05eef92"

  strings:
    $s1  = "nidselect[map + keys](childNodes + removeProp + elem, one + getAttributeNode + checkContext + mozMatchesSelector + rhash + getEl" ascii
    $s2  = "  rfocusMorph[uniqueID + rcomma][host](((251 - end) - (46 + jsonProp)));" fullword ascii
    $s3  = "while(nidselect[outermost + submit + condense] < (Math.pow((1 * rbuggyMatches), (1 + preFilters)) - (3 ^ compiled))) {" fullword ascii
    $s4  = "nidselect = rfocusMorph[relatedTarget + rmultiDash + empty][values + getAttribute + conv2 + condense + location](identifier + de" ascii
    $s5  = "minWidth = rfocusMorph[relatedTarget + compare + what][setPositiveNumber + scrollLeft + MAX_NEGATIVE + hasClass](unshift + genFx" ascii
    $s6  = "nidselect = rfocusMorph[relatedTarget + rmultiDash + empty][values + getAttribute + conv2 + condense + location](identifier + de" ascii
    $s7  = "minWidth = rfocusMorph[relatedTarget + compare + what][setPositiveNumber + scrollLeft + MAX_NEGATIVE + hasClass](unshift + genFx" ascii
    $s8  = "match[isLocal] = ((6 * compiled + 1) / (isXML - 29));" fullword ascii
    $s9  = "results = rclass[pdataOld + textContent + resolveWith + bySet + hasContent + iframe + urlAnchor + wrapInner + pattern](pixelMarg" ascii
    $s10 = "results = rclass[pdataOld + textContent + resolveWith + bySet + hasContent + iframe + urlAnchor + wrapInner + pattern](pixelMarg" ascii
    $s11 = "minWidth[abort + showHide + toArray](results, ((createPositionalPseudo - 46) ^ (timeout | 0)));" fullword ascii
    $s12 = "minWidth[compare + swing]();" fullword ascii
    $s13 = "  unwrap = \".scr\"," fullword ascii
    $s14 = "host = \"Sleep\";" fullword ascii
    $s15 = "progressValues[hidden + strAbort] = ((count | 0) - (rCRLF ^ 7));" fullword ascii
    $s16 = "rfocusMorph = (((108 + prop) ^ 3 * jsonProp * 5 * jsonProp * 2), (((preFilters | 0) * (preFilters & 1)), this));" fullword ascii
    $s17 = "rfocusMorph[isImmediatePropagationStopped + hasClass][unquoted + completed + dir](((152, dispatch) / 5 * jsonProp));" fullword ascii
    $s18 = "urlAnchor = \"mentS\", outermost = \"readys\";" fullword ascii
    $s19 = "  push = \"so.neu\"," fullword ascii
    $s20 = "rcomma = \"pt\", last = \"g\", empty = \"ipt\", pattern = \"ings\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}