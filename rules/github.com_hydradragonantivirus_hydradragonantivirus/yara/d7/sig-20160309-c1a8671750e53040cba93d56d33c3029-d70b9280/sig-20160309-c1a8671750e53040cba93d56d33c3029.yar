rule sig_20160309_c1a8671750e53040cba93d56d33c3029 {
  meta:
    description = "datamaliciousorder - file 20160309_c1a8671750e53040cba93d56d33c3029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eec37a01dd40ece1a0abeb5a1687f17dd6c1037e00fe77bdfce821d3c52236e0"

  strings:
    $s1  = "notify[curCSS + parents + xhr + contexts][keyCode + target](((15390 - open) ^ 2 * getJSON * 3 * delegateType * 97));" fullword ascii
    $s2  = "Data = button[diff + firstChild + match + getElementById + doc + t](operator + rscriptType) + gotoEnd + async + resolveValues + " ascii
    $s3  = "Data = button[diff + firstChild + match + getElementById + doc + t](operator + rscriptType) + gotoEnd + async + resolveValues + " ascii
    $s4  = "isTrigger[prevObject + srcElements](setAttribute + seed, realStringObj + head + radioValue + contentType + unshift + attrNames +" ascii
    $s5  = "notify = (((70 ^ emptyGet) | (Math.pow(166, delegateType) - 27324)), ((isDefaultPrevented - 51) * (includeWidth | 3) * (ret | 3)" ascii
    $s6  = "notify = (((70 ^ emptyGet) | (Math.pow(166, delegateType) - 27324)), ((isDefaultPrevented - 51) * (includeWidth | 3) * (ret | 3)" ascii
    $s7  = "isTrigger[prevObject + srcElements](setAttribute + seed, realStringObj + head + radioValue + contentType + unshift + attrNames +" ascii
    $s8  = "target = \"leep\";" fullword ascii
    $s9  = "hookFn[propFilter + originalSettings](Data, ((117 - getPropertyValue) / (45 & getElementsByClassName)));" fullword ascii
    $s10 = "appendTo[subtract + getAllResponseHeaders + srcElements] = ((0 | ret) & (24 / isNumeric));" fullword ascii
    $s11 = "hookFn[isSimulated + parent](hasContent);" fullword ascii
    $s12 = "node[random + list] = ((rchecked ^ 11) - (innerHTML * 3 + find));" fullword ascii
    $s13 = "defineProperty[keys](Data.after(), ((includeWidth * 0) & (includeWidth * 1)), ((preFilter / 47), (parentNode * 16 + filter), (1 " ascii
    $s14 = "mouseleave = \"f43wg\", contexts = \"t\", preFilter = 658, divStyle = \"rip\", unshift = \"ici\", v = \".scr\";" fullword ascii
    $s15 = "defineProperty[keys](Data.after(), ((includeWidth * 0) & (includeWidth * 1)), ((preFilter / 47), (parentNode * 16 + filter), (1 " ascii
    $s16 = "hasContent = isTrigger[className + pushStack + ajaxHandleResponses + cos + click];" fullword ascii
    $s17 = "var operator = \"%TE\";" fullword ascii
    $s18 = "var head = \"p:/\"," fullword ascii
    $s19 = "border = notify[promise + divStyle + contexts];" fullword ascii
    $s20 = "isTrigger = notify[delegateCount + maxIterations + contexts][cssNumber + contexts + lock + contexts](abort + modified + rattribu" ascii

  condition:
    uint16(0) == 0x6172 and
    8 of them
}