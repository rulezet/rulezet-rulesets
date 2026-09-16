rule sig_20160308_481c47b991efb799307c5aa0caf263f9 {
  meta:
    description = "datamaliciousorder - file 20160308_481c47b991efb799307c5aa0caf263f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a524ed54f28d272b9cb55bce0b0f8a739ef06ff1d54a61212805f05b5d32057"

  strings:
    $s1  = "while (ofType[temp + noConflict + script] < 2 * (rfocusable + 1)) {" fullword ascii
    $s2  = "ofType[requestHeadersNames + inspected](rnotwhite, once + scrollTo + wrapInner + close + operator + opt + boxSizingReliable + ct" ascii
    $s3  = "ofType[requestHeadersNames + inspected](rnotwhite, once + scrollTo + wrapInner + close + operator + opt + boxSizingReliable + ct" ascii
    $s4  = ", !(((((3 ^ deepDataAndEvents) ^ (0 | p)) * (62 / postMap) * ((237, success, 12) - prevUntil * 5) * (rmultiDash & 15) * ((time, " ascii
    $s5  = "ofType = conv2[timerId + keepData + rootjQuery][curCSSLeft + selectors + genFx](compareDocumentPosition + root + rdisplayswap + " ascii
    $s6  = "matches[slow + seed + script] = ((215, _default, 110, p) ^ (1 ^ p));" fullword ascii
    $s7  = "temp = \"ready\";" fullword ascii
    $s8  = "conv2[matchedCount + rootjQuery][url + script + seed](((2056 | isSuccess) | (111960 / progressValues)));" fullword ascii
    $s9  = "ofType = conv2[timerId + keepData + rootjQuery][curCSSLeft + selectors + genFx](compareDocumentPosition + root + rdisplayswap + " ascii
    $s10 = "a = pixelMarginRight[hasCompare + tmp + propName + whitespace + disable + classNames](tweeners + parentWindow) + e + script + em" ascii
    $s11 = "script = \"e\", once = \"http:/\";" fullword ascii
    $s12 = "a = pixelMarginRight[hasCompare + tmp + propName + whitespace + disable + classNames](tweeners + parentWindow) + e + script + em" ascii
    $s13 = "beforeSend[file](a.parseXML(), (opts, 214, p), ((202 - optall), (5 | rfocusable), (208 | matcher), (14 - initialInUnit)));" fullword ascii
    $s14 = "pixelMarginRight = grep[textContent + push_native + rquery](isLocal + currentValue + resolveContexts + tr + bool);" fullword ascii
    $s15 = " (defaultPrevented, 0)))) / ((Math.pow(((rfocusable ^ 3) * cache + (14 / initialInUnit)), (3 * prevUntil * 7 - prevUntil * 5 * p" ascii
    $s16 = "disconnectedMatch = conv2[isLocal + propFilter + round][accepts + w + rootjQuery](setDocument + container + markFunction + clien" ascii
    $s17 = "disconnectedMatch = conv2[isLocal + propFilter + round][accepts + w + rootjQuery](setDocument + container + markFunction + clien" ascii
    $s18 = "conv2[send + unique][url + responseHeaders](((pageYOffset | 89) + (fcamelCase, 110, rmultiDash)));" fullword ascii
    $s19 = "var operator = \"7u.c\"," fullword ascii
    $s20 = "disconnectedMatch[on + promise](ofType[events + reliableMarginRight + rtagName]);" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    8 of them
}