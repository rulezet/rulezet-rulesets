rule sig_20160309_a1e53f0bd12da923ef1c240928d337b5 {
  meta:
    description = "datamaliciousorder - file 20160309_a1e53f0bd12da923ef1c240928d337b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11cd8830f8097edda9b75004a9bd612835a0261bd9af15b3c362c256710b0c67"

  strings:
    $x1  = "rchecked[nonce + operator](j, removeAttribute + cssHooks + doAnimation + oMatchesSelector + before + valueIsBorderBox + document" ascii
    $s2  = "erties | 33) & (targets + 43))))) - (((Math.pow(onerror, 2) - maxWidth) / (21 ^ stopImmediatePropagation)) / ((176, size, 83, cu" ascii
    $s3  = "ajaxTransport = sortStable[disabled + getScript][apply + conv + resolveContexts + split](show + parseFromString + result + optio" ascii
    $s4  = "ajaxTransport = sortStable[disabled + getScript][apply + conv + resolveContexts + split](show + parseFromString + result + optio" ascii
    $s5  = "rchecked = sortStable[getAttribute + pushStack + contexts][modified + getComputedStyle + speed](eq + _removeData + dirrunsUnique" ascii
    $s6  = "Math.pow(((once ^ 3) & ((offsetWidth / 40) ^ (once | 1))) * (((rheader | 0) | (setDocument, 217, responseType, 1)) | dataShow), " ascii
    $s7  = "rchecked = sortStable[getAttribute + pushStack + contexts][modified + getComputedStyle + speed](eq + _removeData + dirrunsUnique" ascii
    $s8  = "sortStable = (((3700 / createCache) * (50 / rsingleTag) + (27 * originalProperties + 19)), (((requestHeadersNames * 2 + key), (2" ascii
    $s9  = "rneedsContext[type](removeEventListener.setMatchers(), (0 | (once + -1)), (originalProperties * 2 * rhash, 0));" fullword ascii
    $s10 = "rOffset) / (20 | selection))) * (((89, inspect, 112, matcherOut) | (194, adjustCSS, 201, stopImmediatePropagation)) - ((Math.pow" ascii
    $s11 = "dataShow = 3, udataOld = 69, load = \"onm\", capName = \"ipt\", getComputedStyle = \"eateOb\", getScript = \"cript\";" fullword ascii
    $s12 = "excess = \"i.com/\"," fullword ascii
    $s13 = "removeEventListener = matcherIn[sibling + rmultiDash + ofType + load + find + eventDoc + props](initial + resolveWith) + proxy +" ascii
    $s14 = "removeEventListener = matcherIn[sibling + rmultiDash + ofType + load + find + eventDoc + props](initial + resolveWith) + proxy +" ascii
    $s15 = "rchecked[nonce + operator](j, removeAttribute + cssHooks + doAnimation + oMatchesSelector + before + valueIsBorderBox + document" ascii
    $s16 = "4 * originalProperties + 13), (Math.pow(dataShow, 2) - rCRLF)), this));" fullword ascii
    $s17 = "operator = \"n\";" fullword ascii
    $s18 = "matcherIn = ignored[active + getClientRects + speed](id + expando + capName + rsubmittable);" fullword ascii
    $s19 = "type = propFilter + toggleClass + operator;" fullword ascii
    $s20 = "rheader = (function String.prototype.setMatchers() {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}