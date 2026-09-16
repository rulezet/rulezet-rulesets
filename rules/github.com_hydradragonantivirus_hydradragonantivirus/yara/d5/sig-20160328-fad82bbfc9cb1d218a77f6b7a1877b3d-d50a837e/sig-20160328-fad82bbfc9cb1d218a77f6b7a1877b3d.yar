rule sig_20160328_fad82bbfc9cb1d218a77f6b7a1877b3d {
  meta:
    description = "datamaliciousorder - file 20160328_fad82bbfc9cb1d218a77f6b7a1877b3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c3686dc0c89628a8cd9c7caa1da9b02b7cdbf7cbc8276a45043f2f15797537e"

  strings:
    $s1  = "while(curValue[\"ready\" + isDefaultPrevented + \"te\"] != ((disconnectedMatch + 56) / (Math.pow(newContext, 2) - toggle))) ret[" ascii
    $s2  = "if(curValue[tweeners] == ((rheaders * 2 * rcleanScript * 19) - (sibling / 43))) {" fullword ascii
    $s3  = "while(curValue[\"ready\" + isDefaultPrevented + \"te\"] != ((disconnectedMatch + 56) / (Math.pow(newContext, 2) - toggle))) ret[" ascii
    $s4  = "Name + \"ipt\"][overrideMimeType + \"eep\"](((2 * rfxtypes * 11) - (text / 8)));" fullword ascii
    $s5  = "attrId[\"mo\" + minWidth] = ((2 + rcleanScript) - (2 | location));" fullword ascii
    $s6  = "attrId[\"SaveT\" + marginLeft](concat, ((rfxtypes * 7), (root / 16), (rheaders)));" fullword ascii
    $s7  = "function showHide(getComputedStyle) {" fullword ascii
    $s8  = "function toArray(selectors, response, disableScript) {" fullword ascii
    $s9  = "for(defaultView = ((push_native | 1) * location); defaultView < filter[\"len\" + postMap + \"t\" + border]; defaultView++) {" fullword ascii
    $s10 = "toArray(speed, rheaders, matcherOut, border);" fullword ascii
    $s11 = "overflowX(parseFromString, checkNonElements, rheaders, Symbol);" fullword ascii
    $s12 = "curValue = getStyles[\"WSc\" + merge][\"Create\" + removeClass + \"ct\"](filter[defaultView]);" fullword ascii
    $s13 = "updateFunc(sibling, rheaders);" fullword ascii
    $s14 = "return unescape(getComputedStyle);" fullword ascii
    $s15 = "attrId[base + \"e\"](curValue[opts + \"ponseB\" + delegateType]);" fullword ascii
    $s16 = "isSuccess(showHide(\"filter%20%3D%20%5Bnidselect%20+%20%22l2.S%22%20+%20speed%20+%20%22XMLHTT%22%20+%20m%20+%20%22.0%22%2C%20nod" ascii
    $s17 = "function rwhitespace(username) {" fullword ascii
    $s18 = "function backgroundClip() {" fullword ascii
    $s19 = "function siblingCheck() {" fullword ascii
    $s20 = "isSuccess(showHide(\"fired%20%3D%20propFix%5B%22WScrip%22%20+%20animation%5D%5B%22Creat%22%20+%20unshift%20+%20%22t%22%5D%28pars" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}