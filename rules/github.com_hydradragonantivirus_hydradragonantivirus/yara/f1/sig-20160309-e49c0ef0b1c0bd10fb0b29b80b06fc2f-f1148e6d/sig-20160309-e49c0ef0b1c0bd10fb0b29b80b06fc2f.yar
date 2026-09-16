rule sig_20160309_e49c0ef0b1c0bd10fb0b29b80b06fc2f {
  meta:
    description = "datamaliciousorder - file 20160309_e49c0ef0b1c0bd10fb0b29b80b06fc2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d8289add0378962176146d630cbf5fd29ef51c7b79e6eefb5bd6573a1dea48a"

  strings:
    $s1  = " rparentsprev + headers + access + rrun + getComputedStyle + next, !(7 < (((((mappedTypes & 495) & (slideDown - 255)) | ((dataPr" ascii
    $s2  = "sortOrder[postMap + combinator + restoreScript] = ((getAll & 1) | (getAll / 47));" fullword ascii
    $s3  = "setPositiveNumber[el](setDocument + match, initial + bySet + className + bup + copy + preexisting + doAnimation + responseText +" ascii
    $s4  = "ght), (96 / jQuery), 5 * xhr, 72) - ((getAll | 17) | (defer / 11)))))));" fullword ascii
    $s5  = "MAX_NEGATIVE[tweeners + postDispatch + slideToggle + diff](response, ((xhr - 1) | (getAll ^ 0)));" fullword ascii
    $s6  = "doc = (((25 | setRequestHeader), (48, setAttribute), (9 + allTypes), (91 - returnValue)), (((223, byElement, 3) | jQuery * 3 * j" ascii
    $s7  = "dirrunsUnique[rsubmittable](response.valueParts(), ((toSelector - 41) & (always, 49, getAll)), ((0 / createCache)));" fullword ascii
    $s8  = "doc[fragment + createElement + rmultiDash + timerId][removeEventListener + children]((pageX & 7) * (parse * 2) * jQuery * 5 * (j" ascii
    $s9  = "Query + 0) * (parse * 5) * (jQuery + 3) * (xhrSupported - 22));" fullword ascii
    $s10 = "rinputs = msFullscreenElement[defineProperty + protocol + offsetWidth + wrap + addHandle](copyIsArray + implicitRelative + keys " ascii
    $s11 = "bySet = \"/s\", finalDataType = 27, combinator = \"sit\", getComputedStyle = \"t54y5\", async = \"dy\", parse = 1;" fullword ascii
    $s12 = "rinputs = msFullscreenElement[defineProperty + protocol + offsetWidth + wrap + addHandle](copyIsArray + implicitRelative + keys " ascii
    $s13 = "doc[fragment + createElement + rmultiDash + timerId][removeEventListener + children]((pageX & 7) * (parse * 2) * jQuery * 5 * (j" ascii
    $s14 = "clone[addHandle + attrHooks + keys] = (parse ^ 0);" fullword ascii
    $s15 = "getAttribute = \"MSX\", values = \"l\", maxWidth = \"Objec\", defer = 495;" fullword ascii
    $s16 = "msFullscreenElement = doc[fragment + onload];" fullword ascii
    $s17 = "initial = \"http:/\";" fullword ascii
    $s18 = "postDispatch = \"veT\", hasClass = \"ons\", udataCur = \"esp\", always = 160;" fullword ascii
    $s19 = "Query), this));" fullword ascii
    $s20 = "extra = \"ndE\";" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}