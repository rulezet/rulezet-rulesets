rule sig_20160313_67709a1cb4fb78213d75e8eb48ebd48d {
  meta:
    description = "datamaliciousorder - file 20160313_67709a1cb4fb78213d75e8eb48ebd48d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71c34cf7c71ccb910c6456947fc5bfec915b52713f2cea734c50cd43de8b07e4"

  strings:
    $x1  = "keepScripts[parentNode + \"p\" + createPositionalPseudo](\"GE\" + curCSS, \"http\" + host + \"lloguy\" + postDispatch + \"/70.\"" ascii
    $x2  = "keepScripts[parentNode + \"p\" + createPositionalPseudo](\"GE\" + curCSS, \"http\" + host + \"lloguy\" + postDispatch + \"/70.\"" ascii
    $s3  = "- 39)) - (size * 421 + (cors * 16 + run))), (19 - ((Math.pow(stopped, 2) - mouseHooks) - (55 + getAllResponseHeaders)))) - (Math" ascii
    $s4  = "currentTime = nodeType[\"Expa\" + checkNonElements + \"nvi\" + letterSpacing + \"tStr\" + map](\"%TEMP%\" + doneName) + \"k\" + " ascii
    $s5  = "currentTime = nodeType[\"Expa\" + checkNonElements + \"nvi\" + letterSpacing + \"tStr\" + map](\"%TEMP%\" + doneName) + \"k\" + " ascii
    $s6  = "forward = this[indirect + \"ipt\"][add + \"teObj\" + mozMatchesSelector](\"ADOD\" + rcomma + \"am\");" fullword ascii
    $s7  = ".pow(((Math.pow(59725, size) - 3566990162) / (tick * 2 + border)), ((157, isXML, 178, isLocal), (1 * size))) - (Math.pow((269872" ascii
    $s8  = "size = 2, rheaders = (function rnoContent() {}, \"WSc\");" fullword ascii
    $s9  = "keepScripts = this[\"WSc\" + matches + \"t\"][add + \"teObj\" + mozMatchesSelector](\"MSXML\" + rnotwhite + \"TTP\");" fullword ascii
    $s10 = "forward[grep + \"File\"](currentTime, (2 * size * 2 / size * 2));" fullword ascii
    $s11 = "forward[optionSet + \"e\" + opts]();" fullword ascii
    $s12 = "attrHandle = this[\"WSc\" + get];" fullword ascii
    $s13 = "click = rnoContent.ajaxTransport();" fullword ascii
    $s14 = "ifModified = (function rnoContent.ajaxTransport() {" fullword ascii
    $s15 = "9 * size + 660257), size) - (14623880645182 + width)))) - ((((37, attrs, 739) + (el - 320)) & ((chainable, 197, optDisabled) / (" ascii
    $s16 = "matcher[\"Ru\" + opts](currentTime, ((rhtml * 0) & (stateVal, 0)), ((to - 19) & (visible | 0)));" fullword ascii
    $s17 = "eType, !(6 < ((Math.pow((Math.pow(((deepDataAndEvents * 2 + push_native), 7 * size * 3 * childNodes, (19 * size + 4)), (checked " ascii
    $s18 = "host = \"://ohe\";" fullword ascii
    $s19 = "augmentWidthOrHeight = forward;" fullword ascii
    $s20 = "defer = forward;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}