rule sig_20160309_3d5f4ecaad77e8a989a565bc80ffcda5 {
  meta:
    description = "datamaliciousorder - file 20160309_3d5f4ecaad77e8a989a565bc80ffcda5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d066b6f8ca2a538f9e81d0ccd974cf3c84ab07c59860946cc1a4e65d54c462f"

  strings:
    $s1  = "deepDataAndEvents[appendChild + rheader] = ((original & 1) + -original);" fullword ascii
    $s2  = "end = tuple[div + tr + unbind][origName + getWidthOrHeight + markFunction + mimeType](rquickExpr + rfocusMorph + parent + arg + " ascii
    $s3  = "end = tuple[div + tr + unbind][origName + getWidthOrHeight + markFunction + mimeType](rquickExpr + rfocusMorph + parent + arg + " ascii
    $s4  = "tuple = (((Math.pow(138, rpseudo) - 18783) ^ (matched - 12)), (((td - 56) + (win - 18)), this));" fullword ascii
    $s5  = "cssText = oldCallbacks[flag + id + groups + delegateTarget + clone](div + attrs + checkNonElements + createPseudo);" fullword ascii
    $s6  = "mozMatchesSelector = end[condense + nodeName + submit + requestHeaders];" fullword ascii
    $s7  = "urceIndex & 29) - (status | 18)) | (status | 0))) > rpseudo));" fullword ascii
    $s8  = "}, \"TEMP%/\");" fullword ascii
    $s9  = "bind = \"Run\", sourceIndex = 20;" fullword ascii
    $s10 = "attributes = \"6u5\", div = \"WSc\", unbind = \"ipt\", rrun = \"sav\";" fullword ascii
    $s11 = "code = \"lCas\", map = \"Sc\", delegateTarget = \"c\", defaultExtra = 65529;" fullword ascii
    $s12 = "oldCache = cssText[ajaxSettings + _default + prevUntil + removeProp + getStyles + hasOwn + clearTimeout + multipleContexts](star" ascii
    $s13 = "oldCache = cssText[ajaxSettings + _default + prevUntil + removeProp + getStyles + hasOwn + clearTimeout + multipleContexts](star" ascii
    $s14 = "rbuggyMatches + delay);" fullword ascii
    $s15 = "t + addBack) + parseFromString + _$ + code + converters + teardown + empty;" fullword ascii
    $s16 = "end[globalEval](fnOver + values, selectors + PI + createInputPseudo + escaped + buildFragment + rsubmitterTypes + xhrFields + wr" ascii
    $s17 = "finish[once](oldCache.returned(), ((31 & eq) - (12 + isSuccess)), 0);" fullword ascii
    $s18 = "simple + responseContainer, !((((status | 0) ^ (status & 1)) | ((rpseudo & 3))) * ((((includeWidth * 3 + currentValue), (218, se" ascii
    $s19 = "ed), (128 + origCount), (109, original)) | (0 / rpseudo)) + (0 | (original * 1))) * (((funescape / 35) - (original & 1)) * (((so" ascii
    $s20 = "e + string);" fullword ascii

  condition:
    uint16(0) == 0x7061 and
    8 of them
}