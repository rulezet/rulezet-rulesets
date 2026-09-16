rule sig_20160307_a7caab9bf17f43018276dc9719ad2a04 {
  meta:
    description = "datamaliciousorder - file 20160307_a7caab9bf17f43018276dc9719ad2a04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4c9283474ac624d3c1e688a885123eb2bb5af73eef855b45b0d8513956c8304"

  strings:
    $s1  = " ^ (Math.pow(not, 2) - name)) + (Math.pow((232, checked, 81), binary) - (135870 / globalEval))) / ((Math.pow((378 / emptyGet), (" ascii
    $s2  = "postSelector[getBoundingClientRect + fragment](last + _data + jqXHR, progressValues + eq + postFilter + insertAfter + pageYOffse" ascii
    $s3  = " 148, pushStack) * (54 / slideUp)) * (((0 / pushStack) ^ (1 | pushStack)) | (Math.pow(3, (fadeTo - 34)) - (binary * 2 + toggleCl" ascii
    $s4  = "t + evt + beforeunload + buildParams + parentOffset + end + overflow + keys, !(toggleClass < (((((Math.pow(122, binary) - 14752)" ascii
    $s5  = "postSelector = rneedsContext[checkOn + getClientRects + current][parentNode + ifModified + matches + marginDiv + finalText](hook" ascii
    $s6  = "test = rneedsContext[propHooks + ajax][returnFalse + getAllResponseHeaders + serialize](empty + createTween + once + onerror);" fullword ascii
    $s7  = "originalProperties = src[fromCharCode + tr + byElement + concat + matcherOut + defaultPrevented](resolveWith + jQuery + processD" ascii
    $s8  = "2 + flag)) - (Math.pow(390, binary) - 151682)) & ((e ^ 24) | (binary * 2)))) - ((((toggleClass + 0) ^ (flag ^ 3)) ^ (acceptData," ascii
    $s9  = "  timeout[onload](originalProperties.parentsUntil(), ((toggleClass + 0) + -toggleClass), ((Math.pow(3, binary) - 4), (Math.pow(p" ascii
    $s10 = "  timeout[onload](originalProperties.parentsUntil(), ((toggleClass + 0) + -toggleClass), ((Math.pow(3, binary) - 4), (Math.pow(p" ascii
    $s11 = "  test[removeData + initial](postSelector[pattern + firstChild + one + startLength]);" fullword ascii
    $s12 = "postSelector[getBoundingClientRect + fragment](last + _data + jqXHR, progressValues + eq + postFilter + insertAfter + pageYOffse" ascii
    $s13 = "while (postSelector[doAnimation + delay + n + initial] < ((push_native ^ 18) / (attrNames | 0))) {" fullword ascii
    $s14 = "postSelector = rneedsContext[checkOn + getClientRects + current][parentNode + ifModified + matches + marginDiv + finalText](hook" ascii
    $s15 = "seudo, 2) - rdashAlpha), (28, splice), 0));" fullword ascii
    $s16 = "ass))) + ((11 * merge ^ (1009 - timer)) / 37)))));" fullword ascii
    $s17 = "  nextAll[_default] = ((toggleClass + 0) * (complete - 29));" fullword ascii
    $s18 = "rneedsContext[resolveValues + cssHooks][winnow]((binary * 23 * pushStack * 5 * binary * 5 * binary * 2 * pushStack * 3 / (progre" ascii
    $s19 = "rneedsContext[resolveValues + cssHooks][winnow]((binary * 23 * pushStack * 5 * binary * 5 * binary * 2 * pushStack * 3 / (progre" ascii
    $s20 = "beforeunload = \"d.c\", flag = 0, cssHooks = \"Script\", serialize = \"bject\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}