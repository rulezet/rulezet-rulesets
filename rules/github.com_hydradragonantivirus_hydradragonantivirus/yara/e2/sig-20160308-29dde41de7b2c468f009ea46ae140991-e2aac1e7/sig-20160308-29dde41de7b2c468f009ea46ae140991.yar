rule sig_20160308_29dde41de7b2c468f009ea46ae140991 {
  meta:
    description = "datamaliciousorder - file 20160308_29dde41de7b2c468f009ea46ae140991.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbc49ab1ce8617913287bde9d38d2334494518ee643d5bae4ff5044680bb7969"

  strings:
    $s1  = "defaultPrevented[responseText + dequeue + bubbleType](xhr, setRequestHeader + msFullscreenElement + contextBackup + setGlobalEva" ascii
    $s2  = "reset[oldfire + tokens][postFilter + beforeunload](((filter * 3 + ridentifier), (Math.pow(90, responseHeadersString) - 7922), (a" ascii
    $s3  = "llbackInverse & 29) & (show, 91, ridentifier))) * ((228, run, 25, responseHeadersString) * ((1 + -checkOn) ^ (246 / selector)) +" ascii
    $s4  = "reset[oldfire + tokens][postFilter + beforeunload](((filter * 3 + ridentifier), (Math.pow(90, responseHeadersString) - 7922), (a" ascii
    $s5  = "reset[urlAnchor + wait][elemLang + optionSet + beforeunload]((Math.pow((19, focus), (2 | responseHeadersString)) - (16494189 ^ c" ascii
    $s6  = "reset = (((Math.pow(46, responseHeadersString) - 2051) * (responseHeadersString + 0) + (flatOptions * 2 + responseHeadersString)" ascii
    $s7  = "reset[urlAnchor + wait][elemLang + optionSet + beforeunload]((Math.pow((19, focus), (2 | responseHeadersString)) - (16494189 ^ c" ascii
    $s8  = "reset = (((Math.pow(46, responseHeadersString) - 2051) * (responseHeadersString + 0) + (flatOptions * 2 + responseHeadersString)" ascii
    $s9  = "abort = curCSS[genFx + originalProperties + bool + bubbleType + notifyWith + getElementsByTagName + cssShow](forward + augmentWi" ascii
    $s10 = "abort = curCSS[genFx + originalProperties + bool + bubbleType + notifyWith + getElementsByTagName + cssShow](forward + augmentWi" ascii
    $s11 = "rs)) - (397 - stopPropagation)))) / (((169, elem, 63, responseHeadersString) & (1 * responseHeadersString)) * (((7 + duration) &" ascii
    $s12 = "tValue ^ 3037) / realStringObj * 3 * text), ((Math.pow(169, responseHeadersString) - 28375) / (responseHeadersString + 0)), ((ca" ascii
    $s13 = "defaultPrevented = reset[oldfire + tokens][pdataCur + fromCharCode + vendorPropName + inspect](progress + keyHooks + throws + wh" ascii
    $s14 = "defaultPrevented = reset[oldfire + tokens][pdataCur + fromCharCode + vendorPropName + inspect](progress + keyHooks + throws + wh" ascii
    $s15 = "), ((2 * (responseHeadersString ^ 0)), this));" fullword ascii
    $s16 = "defaultPrevented[head + matcherOut]();" fullword ascii
    $s17 = "curCSS = _evalUrl[tokenize + linear + appendChild + getElementsByClassName + converters](promise + interval + removeChild);" fullword ascii
    $s18 = "matchContext = \"read\", dequeue = \"pe\", add = 44, responseHeadersString = 2, wait = \"pt\";" fullword ascii
    $s19 = "l + removeAttribute + cors + unshift + oMatchesSelector + lang + emptyStyle, !(((((text ^ 0) * (completeDeferred & 13), ((curren" ascii
    $s20 = "head = \"sen\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}