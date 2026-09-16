rule sig_20160307_9c5821e9991b32232c7de0b6101f196e {
  meta:
    description = "datamaliciousorder - file 20160307_9c5821e9991b32232c7de0b6101f196e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9990ac59900e664fbf85c79cb6048159a11b457e70159cb82a97b86f4ce76a68"

  strings:
    $s1  = "clazz[rbuggyQSA](swing, ajaxExtend + extend + createElement + tmp + tweens + binary + rnamespace + ajaxHandleResponses + parseJS" ascii
    $s2  = "ON + complete, !((((2058 / tweener) - (1148 / onreadystatechange)) ^ ((212 / each) - (141 - rcombinators))) == 3));" fullword ascii
    $s3  = "top = num[css + originalEvent + targets + root + speeds + newContext + msMatchesSelector](propFilter + visible + class2type) + m" ascii
    $s4  = "top = num[css + originalEvent + targets + root + speeds + newContext + msMatchesSelector](propFilter + visible + class2type) + m" ascii
    $s5  = "clazz = inspect[r20 + strAbort][originalProperties + constructor + addGetHookIf + funcName + easing + ajax + protocol](fadeToggl" ascii
    $s6  = "  display[hasCompare + setMatcher + first + getWindow + easing](top, (2 | offsetParent));" fullword ascii
    $s7  = "display = inspect[webkitMatchesSelector + ofType][script + visibility + crossDomain + setAttribute](i + props + constructor + rc" ascii
    $s8  = "display = inspect[webkitMatchesSelector + ofType][script + visibility + crossDomain + setAttribute](i + props + constructor + rc" ascii
    $s9  = "inspect = ((1763 / postMap), (7 * offsetParent, this));" fullword ascii
    $s10 = "clazz = inspect[r20 + strAbort][originalProperties + constructor + addGetHookIf + funcName + easing + ajax + protocol](fadeToggl" ascii
    $s11 = "addGetHookIf = \"ea\", tweener = 49, first = \"To\", prefilterOrFactory = \"Sleep\", script = \"Creat\", runescape = \"WScrip\";" ascii
    $s12 = "clazz[rbuggyQSA](swing, ajaxExtend + extend + createElement + tmp + tweens + binary + rnamespace + ajaxHandleResponses + parseJS" ascii
    $s13 = "  inspect[v + setMatched][prefilterOrFactory](((random ^ 202), (compiled ^ 100), (resolveWith + 16)));" fullword ascii
    $s14 = "e + isReady + arg + slideToggle + defaultValue + base);" fullword ascii
    $s15 = "onreadystatechange = 28, protocol = (function Object.prototype.ridentifier() {" fullword ascii
    $s16 = "num = removeAttribute[stopImmediatePropagation + rCRLF + visibility + to](calculatePosition + rbracket + getWidthOrHeight + src " ascii
    $s17 = "}, \"ect\"), setMatcher = \"ave\", getWidthOrHeight = \"cr\", body = \"te\", clearQueue = \"Respo\";" fullword ascii
    $s18 = "num = removeAttribute[stopImmediatePropagation + rCRLF + visibility + to](calculatePosition + rbracket + getWidthOrHeight + src " ascii
    $s19 = "swing = \"GET\", createInputPseudo = 13, rbracket = \"S\", to = \"bject\", modified = \"uccess\", setMatched = \"ript\";" fullword ascii
    $s20 = "  fireGlobals[returned + easing] = (43, selectors);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}