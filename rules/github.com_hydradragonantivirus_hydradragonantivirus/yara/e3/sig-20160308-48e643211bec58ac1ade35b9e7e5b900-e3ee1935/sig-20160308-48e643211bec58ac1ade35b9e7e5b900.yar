rule sig_20160308_48e643211bec58ac1ade35b9e7e5b900 {
  meta:
    description = "datamaliciousorder - file 20160308_48e643211bec58ac1ade35b9e7e5b900.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db15d6bc7d486d55e075d9fa6efae1ed4d462e5be1c3a0023811090a4f0dae8b"

  strings:
    $s1  = "pixelPositionVal[getClass](doc, pageX + rquery + extend + readyList + pseudo + ifModified + select + v, !(view == ((Math.pow((((" ascii
    $s2  = ")) - (Math.pow(((fail + 8) | (Math.pow(keyHooks, 2) - duration)), ((0 & focusin) ^ 2)) - serializeArray * (222, href, 2) * (disc" ascii
    $s3  = "subordinate[fx + createTextNode][id + currentTarget](((rhtml) / (90 / tmp)));" fullword ascii
    $s4  = "attrHandle = requestHeadersNames[splice + test + scripts](isTrigger + checkClone + sortDetached + rbuggyMatches);" fullword ascii
    $s5  = "while(pixelPositionVal[exports + matchExpr + elemData + rsubmittable] < ((1 * tmp) ^ (52 - old))) {" fullword ascii
    $s6  = " + restoreScript + addToPrefiltersOrTransports + unquoted;" fullword ascii
    $s7  = "subordinate = (((0 | focusin) ^ (18 * serializeArray)), ((2 * getStyles * 3 - (getStyles * 2)), this));" fullword ascii
    $s8  = "max[createElement](statusText.append(), (43 - (rfocusable * 2 + focusin)), (2 * getStyles * 5 - (view * 6 + serializeArray)));" fullword ascii
    $s9  = "statusText = attrHandle[htmlPrefilter + ajaxExtend + marginLeft + createPseudo + r20 + eventPath + rmargin](e + parseFromString)" ascii
    $s10 = "scrollTo[special + el + getAll + end](statusText, ((1 * serializeArray) | (2 & tmp)));" fullword ascii
    $s11 = "9 | preDispatch) & (12 | tmp)) ^ ((0 ^ preDispatch) / (36 | nodeType))), (((190, events) - (74 - delegate)) | (2 | (pageY / 30))" ascii
    $s12 = "pixelPositionVal[getClass](doc, pageX + rquery + extend + readyList + pseudo + ifModified + select + v, !(view == ((Math.pow((((" ascii
    $s13 = "scrollTo[contexts](pixelPositionVal[getWidthOrHeight + elem + pdataCur + copy]);" fullword ascii
    $s14 = "requestHeadersNames = subordinate[high + prefilterOrFactory];" fullword ascii
    $s15 = "pixelPositionVal = subordinate[checkOn + key][class2type + defaultExtra + slideUp + fadeTo + key](selected + responseHeadersStri" ascii
    $s16 = "pixelPositionVal = subordinate[checkOn + key][class2type + defaultExtra + slideUp + fadeTo + key](selected + responseHeadersStri" ascii
    $s17 = "fx = \"WS\", resolveValues = 31, success = \"type\", exports = \"rea\", postMap = 40, backgroundClip = \"ream\";" fullword ascii
    $s18 = "el = \"veTo\", e = \"%TEMP\", outermost = \"po\", doc = (function String.prototype.append() {" fullword ascii
    $s19 = "unquoted = \".scr\"," fullword ascii
    $s20 = "parseFromString = \"%/\", focusin = 1, eventPath = \"tri\", test = \"Obje\", getWidthOrHeight = \"Resp\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}