rule sig_20160308_f63274c3ccde38b7ee5c9511e1366b5b {
  meta:
    description = "datamaliciousorder - file 20160308_f63274c3ccde38b7ee5c9511e1366b5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74f42c0d21cd4e99abf653ee9a493664a42d6dfa1b85f3893f5b54ee605a5daf"

  strings:
    $s1  = "excess[random + originalOptions + resolveContexts](success, ((0 / hash) ^ (45 - getComputedStyle)));" fullword ascii
    $s2  = "isArray[checked] = (getComputedStyle - (25 ^ jsonp));" fullword ascii
    $s3  = "excess = teardown[grep + rquickExpr + compareDocumentPosition + rkeyEvent][adown + implicitRelative + removeClass + lastModified" ascii
    $s4  = "rsubmittable[nextSibling + curElem](getStyles, mapped + position + accepts + valueParts + elemdisplay + curLeft + removeAttribut" ascii
    $s5  = "teardown[global + rkeyEvent][rcombinators + className](((elementMatchers / 40) | (hash * 9 + one)));" fullword ascii
    $s6  = "teardown[jqXHR + setOffset + nativeStatusText + position][animated](((Math.pow(3382, exports) - 11431806) * (trim, 35, exports) " ascii
    $s7  = "teardown = (((Math.pow(23, exports) - 489) ^ (Math.pow(attr, 2) - ajaxPrefilter)), (((2 ^ unshift) & (157, JSON, 238, amd)), thi" ascii
    $s8  = "teardown = (((Math.pow(23, exports) - 489) ^ (Math.pow(attr, 2) - ajaxPrefilter)), (((2 ^ unshift) & (157, JSON, 238, amd)), thi" ascii
    $s9  = "delegate, 2) - activeElement), (Math.pow(167, exports) - 27711), unshift) * (2 ^ (one + 0)) * (childNodes - 4), (Math.pow(((json" ascii
    $s10 = " * exports * 3 * amd))) - (((1 * one) * (1 * exports)) * ((36 - then) + (30 - factory)) * (2 * exports * 2 * amd * 2, (Math.pow(" ascii
    $s11 = "rsubmittable = teardown[jqXHR + ontype][speeds + outermost + prepend + letterSpacing](adjustCSS + relatedTarget + swap);" fullword ascii
    $s12 = "teardown[jqXHR + setOffset + nativeStatusText + position][animated](((Math.pow(3382, exports) - 11431806) * (trim, 35, exports) " ascii
    $s13 = "th = teardown[grep + cur + rkeyEvent];" fullword ascii
    $s14 = "implementation = \"%TEMP%\"," fullword ascii
    $s15 = "excess = teardown[grep + rquickExpr + compareDocumentPosition + rkeyEvent][adown + implicitRelative + removeClass + lastModified" ascii
    $s16 = "settings[extend + rsibling + fadeOut] = ((0 ^ key) ^ (30 - deep));" fullword ascii
    $s17 = " + set + position](getById + noConflict + xhrFields + copyIsArray);" fullword ascii
    $s18 = "rsubmittable[nextSibling + curElem](getStyles, mapped + position + accepts + valueParts + elemdisplay + curLeft + removeAttribut" ascii
    $s19 = "excess[orig + compareDocumentPosition + originalEvent](rsubmittable[firstElementChild + outermostContext + nodes]);" fullword ascii
    $s20 = "while(rsubmittable[eventPath + radio + position + elementMatcher + qsa] < ((12 / boolHook) ^ 5)) {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}