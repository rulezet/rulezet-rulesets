rule sig_20160311_42bf17a9de9ad644f8c6c99f737c6130 {
  meta:
    description = "datamaliciousorder - file 20160311_42bf17a9de9ad644f8c6c99f737c6130.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "253f7e7e5afb0c87ba285450c10e65d80137d94ad48352a848b22a41962eaa05"

  strings:
    $s1  = "responseType[optgroup + \"p\" + multipleContexts + \"n\"](attributes + \"E\".class2type() + isSuccess, \"http\" + disabled + \"s" ascii
    $s2  = "), (179 & responseHeaders))), (((24 | domManip) | (Math.pow(6, wrap) - 26)), ((Math.pow(crossDomain, 2) - isReady) * (67 - byEle" ascii
    $s3  = "ment) + (10 - parsed)), ((150 + opts)), (53 * wrap & (276 - seekingTransport))), ((3 / handlers) | (6 & parsed)), ((Math.pow((20" ascii
    $s4  = "requestHeaders[\"t\" + speed + \"e\"] = ((6 - isImmediatePropagationStopped) + (1 & funcName));" fullword ascii
    $s5  = "traditional = (((43 & deepDataAndEvents) * (5 | isImmediatePropagationStopped) + (Math.pow(4, wrap) - 11)), ((isImmediatePropaga" ascii
    $s6  = "pageX = \"%TEMP%\"," fullword ascii
    $s7  = " | isReady), (1 + rclass)) - (Math.pow(701, wrap) - 490489)) / (parsed * 2 * parsed * 3 * handlers / (5 * handlers + 3)))) * (((" ascii
    $s8  = "before = traditional[\"WScri\" + elementMatcher][\"Cre\" + rneedsContext + \"bje\".class2type() + notifyWith](\"ADO\" + Symbol +" ascii
    $s9  = "traditional = (((43 & deepDataAndEvents) * (5 | isImmediatePropagationStopped) + (Math.pow(4, wrap) - 11)), ((isImmediatePropaga" ascii
    $s10 = "requestHeaders = before;" fullword ascii
    $s11 = "which = timer[offsetParent + \"Objec\" + appendChild](\"WScrip\".class2type() + getClientRects + \"ell\");" fullword ascii
    $s12 = "before[\"sav\".class2type() + matchIndexes + \"File\"](hasContent, ((62 / isTrigger) & (3 & handlers)));" fullword ascii
    $s13 = "hasContent = which[linear + \"dEnvir\" + MAX_NEGATIVE + \"ent\".class2type() + unmatched + \"ings\"](pageX + \"/\") + triggerHan" ascii
    $s14 = "hasContent = which[linear + \"dEnvir\" + MAX_NEGATIVE + \"ent\".class2type() + unmatched + \"ings\"](pageX + \"/\") + triggerHan" ascii
    $s15 = "responseHeaders = 245, ajaxConvert = \".\", crossDomain = 6, linear = \"Expan\", handlers = 3;" fullword ascii
    $s16 = "wrap / 2) * wrap) * ((1 + funcName) * (2 + funcName)) * ((31 - specified) + (1 - rclass)) + (0 | (rclass))))));" fullword ascii
    $s17 = "timer = traditional[responseContainer + \"pt\"];" fullword ascii
    $s18 = "responseType[optgroup + \"p\" + multipleContexts + \"n\"](attributes + \"E\".class2type() + isSuccess, \"http\" + disabled + \"s" ascii
    $s19 = "return width" fullword ascii
    $s20 = "responseType = traditional[\"WScr\" + propFilter][\"Cre\".class2type() + deep + \"Object\"](ownerDocument + \"ML2.X\" + charset " ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}