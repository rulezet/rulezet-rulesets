rule sig_20160311_71a5dd8044d9bfc6dde692354a69fe39 {
  meta:
    description = "datamaliciousorder - file 20160311_71a5dd8044d9bfc6dde692354a69fe39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beae30ae23193c78c1587556cc5354bf7c0570b2654c787660f388c746e76a4e"

  strings:
    $s1  = "+ responseHeadersString), (7 - ajaxHandleResponses)) - (Math.pow((27967 + what), (2 & firstChild)) - (2909241828 - cssProps))), " ascii
    $s2  = "adown[\"o\" + diff + \"en\".stopQueue()](focusin + \"T\", isImmediatePropagationStopped + \"//thai\" + appendTo + \"biz/b\".stop" ascii
    $s3  = "round + \"ethai\" + isDefaultPrevented + \"/43\" + lastChild, !(5 < (((Math.pow(mouseHooks * 5 * firstChild, (55, username, 2)) " ascii
    $s4  = "adown = onabort[\"WScrip\" + nodeNameSelector][\"Creat\" + offsetParent + \"ect\".stopQueue()](win + \"2.X\" + manipulationTarge" ascii
    $s5  = "ajaxHandleResponses = 5, manipulationTarget = \"MLHTTP\", removeEvent = (function Object.prototype.stopQueue() {" fullword ascii
    $s6  = "protocol + 473)), ((newCache * 4 + mouseleave) / (Math.pow(3, firstChild) - 5)), ((requestHeadersNames * 2 + ajaxHandleResponses" ascii
    $s7  = "((2 * firstChild * 2 * firstChild * 2 * firstChild - (3 & mouseHooks)), (Math.pow(2 * firstChild * 7, (define, 174, firstChild))" ascii
    $s8  = ") | (167 + attrs)), ((2 * method + 1) - (pattern - 32))) * ((Math.pow((optSelected / 5) * (pattern, 69, n) * (2 + matcher) * (2 " ascii
    $s9  = "open = gotoEnd[current + \"Enviro\" + guaranteedUnique + \"tSt\".stopQueue() + height](\"%TEMP\" + css) + \"optgro\" + ct + \".s" ascii
    $s10 = "open = gotoEnd[current + \"Enviro\" + guaranteedUnique + \"tSt\".stopQueue() + height](\"%TEMP\" + css) + \"optgro\" + ct + \".s" ascii
    $s11 = "_data[\"R\" + callbackExpect + \"n\".stopQueue()](open.stopQueue(((getText, 123) & (display & 93))), responseHeadersString, (1 +" ascii
    $s12 = "gotoEnd = cssPrefixes[origType + \"Obj\" + stopImmediatePropagation](\"WScr\".stopQueue() + timer + \"Shell\");" fullword ascii
    $s13 = "_data[\"R\" + callbackExpect + \"n\".stopQueue()](open.stopQueue(((getText, 123) & (display & 93))), responseHeadersString, (1 +" ascii
    $s14 = " - (138 + writable))), (((33 | n) / (75 / cssExpand)) + ((372 - tweener) - (1 * firstChild))), (((1 + -matcher) | (192 / scrollT" ascii
    $s15 = "nodeType = onabort[\"WScrip\" + nodeNameSelector][\"Crea\" + prefilterOrFactory + \"ect\".stopQueue()](checkDisplay + \"DB.S\" +" ascii
    $s16 = "nodeType = onabort[\"WScrip\" + nodeNameSelector][\"Crea\" + prefilterOrFactory + \"ect\".stopQueue()](checkDisplay + \"DB.S\" +" ascii
    $s17 = "nodeType[\"saveTo\" + rCRLF](open, ((1 | responseHeadersString) + 1));" fullword ascii
    $s18 = "getText = 244, cssProps = 1074373443, writable = 591, updateFunc = \"ose\", win = \"MSXML\", css = \"%/\";" fullword ascii
    $s19 = "classes[nodeNameSelector + \"yp\" + setDocument] = ((1 + responseHeadersString) + 0);" fullword ascii
    $s20 = "teardown[\"cl\" + updateFunc]();" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    8 of them
}