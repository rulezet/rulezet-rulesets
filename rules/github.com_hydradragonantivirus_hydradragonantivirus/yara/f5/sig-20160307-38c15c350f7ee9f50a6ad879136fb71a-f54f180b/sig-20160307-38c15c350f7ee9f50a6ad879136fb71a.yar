rule sig_20160307_38c15c350f7ee9f50a6ad879136fb71a {
  meta:
    description = "datamaliciousorder - file 20160307_38c15c350f7ee9f50a6ad879136fb71a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59303588fde044d6afdd14bf668341b4c42be4522b2d6adff92172e93d625cdd"

  strings:
    $s1  = "domManip[augmentWidthOrHeight + getScript](seekingTransport, oMatchesSelector + exports + unloadHandler + tweens + then + click " ascii
    $s2  = "dispatch[cssFn](amd.createTextNode(), ((Math.pow(rcombinators, 2) - support), (203 & opt), (1 + -noConflict)), ((34 | createButt" ascii
    $s3  = "text[matchAnyContext + target][handler + getAllResponseHeaders](((127 * oldfire + 13) | (Math.pow(relative, 2) - notifyWith)));" fullword ascii
    $s4  = "text[dataAttr + getAllResponseHeaders + target][minWidth + statusCode]((accepts * 2 * byElement - (24 & opacity)));" fullword ascii
    $s5  = "domManip[augmentWidthOrHeight + getScript](seekingTransport, oMatchesSelector + exports + unloadHandler + tweens + then + click " ascii
    $s6  = "until = text[backgroundClip + hasCompare + responseHeaders + target];" fullword ascii
    $s7  = "dispatch[cssFn](amd.createTextNode(), ((Math.pow(rcombinators, 2) - support), (203 & opt), (1 + -noConflict)), ((34 | createButt" ascii
    $s8  = "accepts = 2, configurable = \"type\", adown = \"n\", processData = 42;" fullword ascii
    $s9  = "isHidden = text[defaultView + run + target][head + cssHooks + pageY + useCache](optDisabled + Deferred + throws);" fullword ascii
    $s10 = "createComment = until[rquery + _$ + filter + writable + markFunction + target](focus + callback + relatedTarget + speed + getEle" ascii
    $s11 = "amd = createComment[soFar + rfocusMorph + stored + rcomma + simulate + callback + serializeArray + targets](clone + memory + css" ascii
    $s12 = "createComment = until[rquery + _$ + filter + writable + markFunction + target](focus + callback + relatedTarget + speed + getEle" ascii
    $s13 = "amd = createComment[soFar + rfocusMorph + stored + rcomma + simulate + callback + serializeArray + targets](clone + memory + css" ascii
    $s14 = "((interval & 151)))), ((((pageYOffset, 36, truncate) - (3 * requestHeaders + 2)) / ((constructor & 3) | (cors - 43))) + (((code " ascii
    $s15 = " (window + 4963))) - (((Math.pow(byElement, 2) - elementMatcher), (217 & reliableMarginLeftVal), (Math.pow(7, accepts) - 41)) | " ascii
    $s16 = "isHidden[response + once](domManip[self + document + whitespace + scripts]);" fullword ascii
    $s17 = "target = \"t\"," fullword ascii
    $s18 = "domManip = text[backgroundClip + offset][fnOver + ret + msMatchesSelector](addGetHookIf + minWidth + split + addGetHookIf + orig" ascii
    $s19 = "domManip = text[backgroundClip + offset][fnOver + ret + msMatchesSelector](addGetHookIf + minWidth + split + addGetHookIf + orig" ascii
    $s20 = "text = (2 * (constructor) * (2 + noConflict) * (2 | accepts) * (2 & accepts) * (1 * accepts) * (3 & accepts), ((17 * oldfire - (" ascii

  condition:
    uint16(0) == 0x6977 and
    8 of them
}