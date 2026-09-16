rule sig_20160307_6de875721380eecbbff9d95b7bcb763b {
  meta:
    description = "datamaliciousorder - file 20160307_6de875721380eecbbff9d95b7bcb763b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2f4d5e233d6e8746a5ba4bd06721589ae9f02a0dabcb60ee776ad4b3efdcb0a"

  strings:
    $s1  = "setMatched[invert](callback, getWindow + nextUntil + keyHooks + hover + beforeunload + updateFunc + interval + ifModified + lett" ascii
    $s2  = "rtagName[getScript + srcElements + inspect]();" fullword ascii
    $s3  = "shift[_queueHooks + unloadHandler][timerId + childNodes](((Math.pow(9, defineProperty) - 70) ^ (ajaxTransport - 60)));" fullword ascii
    $s4  = "oreScript) - (561 + booleans)) / ((0 | offsetHeight) - (39 - start)))) & (((5 * state - (15 | defineProperty)) - (0 ^ (children " ascii
    $s5  = "shift = (((Math.pow(17, defineProperty) - 257) + (state * 7 + noBubble)), (((91, status, 20) & (Math.pow(remaining, 2) - fragmen" ascii
    $s6  = "while(setMatched[preventDefault + elems + undelegate] < (Math.pow((2 + soFar), (0 | defineProperty)) - (4 + soFar))) {" fullword ascii
    $s7  = "shift = (((Math.pow(17, defineProperty) - 257) + (state * 7 + noBubble)), (((91, status, 20) & (Math.pow(remaining, 2) - fragmen" ascii
    $s8  = "mappedTypes = stopped + disableScript;" fullword ascii
    $s9  = "rtagName[promise + fromCharCode + delegateTarget + classCache](letterSpacing, (1 + soFar));" fullword ascii
    $s10 = "rtagName[srcElements + host]();" fullword ascii
    $s11 = "setMatched = shift[m + byElement + append][rdashAlpha + list + node + append](scrollTo + contentDocument + src + contentDocument" ascii
    $s12 = "rtagName = shift[head + append][nonce + rnotwhite + elements + initial](tweens + source + attrId);" fullword ascii
    $s13 = "setMatched = shift[m + byElement + append][rdashAlpha + list + node + append](scrollTo + contentDocument + src + contentDocument" ascii
    $s14 = "setMatched[invert](callback, getWindow + nextUntil + keyHooks + hover + beforeunload + updateFunc + interval + ifModified + lett" ascii
    $s15 = "er, !(((((7 ^ (createInputPseudo + 97)) ^ ((pixelPositionVal ^ 98) * (cacheURL, 2) + (Math.pow(next, 2) - win))) / (((385 ^ rest" ascii
    $s16 = "parseHTML = shift[configurable + sibling + append];" fullword ascii
    $s17 = "var host = \"pen\";" fullword ascii
    $s18 = "head = \"WScrip\"," fullword ascii
    $s19 = "elementMatchers[fadeToggle + append + reliableMarginRight] = (0 / e);" fullword ascii
    $s20 = " + createPositionalPseudo + submit);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}