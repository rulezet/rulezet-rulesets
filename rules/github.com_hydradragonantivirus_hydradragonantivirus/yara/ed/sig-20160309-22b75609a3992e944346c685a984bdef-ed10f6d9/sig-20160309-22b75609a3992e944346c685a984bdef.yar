rule sig_20160309_22b75609a3992e944346c685a984bdef {
  meta:
    description = "datamaliciousorder - file 20160309_22b75609a3992e944346c685a984bdef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec598cdd588053cac2e332ec9e027072e90be901d1795c41e4dc9132913e1b08"

  strings:
    $s1  = "onerror = buildFragment[noBubble + curCSS + initial + context + propName + password + off](div1 + push_native) + unmatched + pre" ascii
    $s2  = "end[dataAndEvents + handlers][nidselect](((Math.pow(filters, 2) - xml), (133, version, 43, code), 57, (keyCode | 8856)));" fullword ascii
    $s3  = "onerror = buildFragment[noBubble + curCSS + initial + context + propName + password + off](div1 + push_native) + unmatched + pre" ascii
    $s4  = "idx[position](firstDataType, needsContext + scrollTo + text + tmp + _$ + hidden + easing + global + oldfire + state + handleObjI" ascii
    $s5  = "idx[position](firstDataType, needsContext + scrollTo + text + tmp + _$ + hidden + easing + global + oldfire + state + handleObjI" ascii
    $s6  = "currentTime[interval](onerror.el(), (finalText | (1 + -done)), ((1 * finalText) / (5 + matches)));" fullword ascii
    $s7  = "end = (((69 | num) + (70, escaped, 253, l)), (((22 - addBack) ^ (148, tick, 59, hasScripts)), this));" fullword ascii
    $s8  = "pendTo + root + exports + rejectWith;" fullword ascii
    $s9  = "idx = end[list + support + rlocalProtocol][attachEvent + animation + rlocalProtocol](responseHeaders + stop + jsonp + indirect);" ascii
    $s10 = "winnow[fadeOut + swap + rcheckableType] = ((finalText ^ 1) + -(select, 25, createFxNow, 1));" fullword ascii
    $s11 = "n + serializeArray + self + isTrigger + clientTop + isEmptyObject, !(2 == (((Math.pow(((finalText | 0) | (rmultiDash, 60, matche" ascii
    $s12 = "async [isReady + write + define]();" fullword ascii
    $s13 = "contentDocument = 185, text = \"//ngu\", xml = 3616, matches = 3, num = 112, filters = 61;" fullword ascii
    $s14 = "responseHeaders = \"MSX\", createOptions = \"spons\", noBubble = \"E\", l = 104, animation = \"Objec\", self = \"g\";" fullword ascii
    $s15 = "position = \"open\", firstDataType = \"GET\", i = \"ipt\";" fullword ascii
    $s16 = "easing = \"thongt\", needsContext = \"ht\", oldfire = \"m/sy\", hidden = \"ng\";" fullword ascii
    $s17 = "prependTo = \"llback\", oldCallbacks = 48, password = \"in\", indirect = \"TTP\", prevObject = \"W\";" fullword ascii
    $s18 = "s)), ((1 + -done) ^ 2)) - ((oldCallbacks / 8) & (done * 5))) - ((done ^ 31) - (scale + 8))) & ((matches - 1) * eq * (2 & matches" ascii
    $s19 = "cacheURL = \"ADODB.\", propName = \"entStr\", pseudo = \"bjec\", div1 = \"%TEMP\", eq = 2;" fullword ascii
    $s20 = "var version = 252," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}