rule sig_20160307_0f3be18c702159a2d871f1670c09b6f2 {
  meta:
    description = "datamaliciousorder - file 20160307_0f3be18c702159a2d871f1670c09b6f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "017b2205807ef192f01d23602aa639cad0df785444e1c530cedb18876b5b83bc"

  strings:
    $s1  = "stop[status](rsubmitterTypes + getScript, checked + inspectPrefiltersOrTransports + each + uid + rcombinators + jsonp + callback" ascii
    $s2  = "delegateTarget[proxy + checkbox] = ((1 & clearQueue) * (1 * clearQueue));" fullword ascii
    $s3  = "stop[status](rsubmitterTypes + getScript, checked + inspectPrefiltersOrTransports + each + uid + rcombinators + jsonp + callback" ascii
    $s4  = "raw[optDisabled + rtagName + pixelPosition][not + content + createDocumentFragment + createDocumentFragment + _load](((scrollLef" ascii
    $s5  = "Inverse + className + expanded, !(((((101, fn)) - ((Math.pow(37, cssNormalTransform) - (1143 + responseHeaders)) / ((127 - respo" ascii
    $s6  = "speed = 25, getScript = \"T\", readyWait = \"o\", rprotocol = \"ect\", handlerQueue = \".Shel\";" fullword ascii
    $s7  = "t / 27) + (Math.pow(second, 2) - reliableMarginLeft)));" fullword ascii
    $s8  = "stop = raw[appendChild + configurable + rquickExpr][fail + constructor + dataPriv](pageYOffset + resolveWith + unloadHandler + s" ascii
    $s9  = "stop = raw[appendChild + configurable + rquickExpr][fail + constructor + dataPriv](pageYOffset + resolveWith + unloadHandler + s" ascii
    $s10 = "tbody[win + curCSSTop + setRequestHeader + createDocumentFragment](first, ((6 / fn) | (0 / speed)));" fullword ascii
    $s11 = "handleObj = duration[r20 + dataPriv](optDisabled + expando + nid + handlerQueue + content);" fullword ascii
    $s12 = "raw[optDisabled + rtagName + pixelPosition][not + content + createDocumentFragment + createDocumentFragment + _load](((scrollLef" ascii
    $s13 = "nseContainer), (7 + ajaxPrefilter)))) | (((1 | isSuccess) + -(3 / fn)) | (((6 - checkOn) | (2 | display)) - ((29 & promise) / (1" ascii
    $s14 = "raw[ajaxExtend + tweens][add](((16264 - outermost) ^ (1697 + toggle)));" fullword ascii
    $s15 = "tbody[readyWait + checkbox + extra]();" fullword ascii
    $s16 = "tbody = raw[appendChild + isXML + pixelPosition][fail + factory + rnotwhite + rprotocol](documentElement + orig);" fullword ascii
    $s17 = "while (stop[curCSS + what + dataTypeOrTransport] < ((cssNormalTransform) + 2)) {" fullword ascii
    $s18 = "appendChild = \"W\", second = 49, responseContainer = 16, dataTypeOrTransport = \"te\", rcombinators = \"a.c\", rsubmitterTypes " ascii
    $s19 = "appendChild = \"W\", second = 49, responseContainer = 16, dataTypeOrTransport = \"te\", rcombinators = \"a.c\", rsubmitterTypes " ascii
    $s20 = "first = handleObj[clientX + select + extra + matcherIn + percent + createPseudo + jsonpCallback + register](option + responseHea" ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}