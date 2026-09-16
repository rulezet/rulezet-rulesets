rule sig_20160308_7113677bdc4d40664ed4a365e0d5e7e3 {
  meta:
    description = "datamaliciousorder - file 20160308_7113677bdc4d40664ed4a365e0d5e7e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71054ebc0811d2e9b1c36a73d127f8a2a94b71cc98b2474a83bee4e2b58f2a65"

  strings:
    $s1  = "animate[serializeArray + owner][script + step + boxSizingReliableVal](((Math.pow(r20, 2) - map), (15337 - nonce)));" fullword ascii
    $s2  = "while (getWidthOrHeight[parents + name] < ((2356 / before) / (Math.pow(21, what) - 410))) {" fullword ascii
    $s3  = "animate[serializeArray + v + propFix][etag]((next | (Math.pow(54, what) - 2816)));" fullword ascii
    $s4  = "resolveValues = animate[deep + simulate][delegateTarget + scale + headers + self](createOptions + wrapAll + document + css);" fullword ascii
    $s5  = "getWidthOrHeight[children + reverse]();" fullword ascii
    $s6  = "getWidthOrHeight[image + dataTypes](rquery, fireWith + keepData + pop + rcheckableType + buildFragment + dataTypes + text + fn +" ascii
    $s7  = "resolveValues[rheader](getWidthOrHeight[option + fragment + nativeStatusText + ajaxConvert]);" fullword ascii
    $s8  = "getWidthOrHeight = animate[acceptData + propFix][t + selectedIndex + orig](window + write + container + ajaxSettings + ajaxSetti" ascii
    $s9  = "postDispatch[matcher + prevObject] = ((funescape - 14) ^ (on - 3));" fullword ascii
    $s10 = "getWidthOrHeight[image + dataTypes](rquery, fireWith + keepData + pop + rcheckableType + buildFragment + dataTypes + text + fn +" ascii
    $s11 = "animate = (((1 + -mappedTypes) | (17 * max + 15)), (((mappedTypes ^ 0) + -(next | 1)), this));" fullword ascii
    $s12 = " pageY, !((((((has - 9) | (rfocusMorph, 29)) ^ ((inspected - 74), (param, 195), (fixHook, 58), (selection + 6))) ^ (((inArray, 1" ascii
    $s13 = "bup = handleObjIn[rsingleTag + dataAttr + hide + MAX_NEGATIVE + dirruns + list](isImmediatePropagationStopped + timeoutTimer) + " ascii
    $s14 = "bup = handleObjIn[rsingleTag + dataAttr + hide + MAX_NEGATIVE + dirruns + list](isImmediatePropagationStopped + timeoutTimer) + " ascii
    $s15 = "script = \"Sl\", fragment = \"s\", inspected = 182, dataAttr = \"Envi\", list = \"gs\";" fullword ascii
    $s16 = "getWidthOrHeight = animate[acceptData + propFix][t + selectedIndex + orig](window + write + container + ajaxSettings + ajaxSetti" ascii
    $s17 = "75, fireGlobals) & (7 ^ createButtonPseudo)) * ((160, matcherFromGroupMatchers, 30) & (context | 21)) + ((mappedTypes | 2) & (on" ascii
    $s18 = "resolveValues[fragment + responseText + PI](bup, ((next | 1) * (what ^ 0)));" fullword ascii
    $s19 = "t)) * (0 ^ (mappedTypes ^ 3)) + ((next | 1) * (next ^ 1))))) > needsContext));" fullword ascii
    $s20 = "adown + bool + file + fast;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}