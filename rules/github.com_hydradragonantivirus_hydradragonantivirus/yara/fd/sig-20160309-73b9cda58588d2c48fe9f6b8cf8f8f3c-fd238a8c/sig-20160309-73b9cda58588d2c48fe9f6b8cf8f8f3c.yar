rule sig_20160309_73b9cda58588d2c48fe9f6b8cf8f8f3c {
  meta:
    description = "datamaliciousorder - file 20160309_73b9cda58588d2c48fe9f6b8cf8f8f3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c08120758b9972d0c0712d2bff54cac065b3bae5aef0c3e6f5cb7bad91422ef"

  strings:
    $s1  = "genFx[seed + pnum](cos, dispatch + notify + target + curPosition + delegateCount + origName + originalEvent + bp + always + chec" ascii
    $s2  = "mouseleave[host + selection] = ((0 & addBack) ^ (13 - scriptCharset));" fullword ascii
    $s3  = "Local | 1)))), (((isLocal | (3520 / qsaError)), ((827 + tweeners) / (0 | pixelMarginRightVal))) - (Math.pow(((5 | getJSON) * (1 " ascii
    $s4  = "(Math.pow(26, mouseenter) - 645)))), ((((position, 165, addBack)) + 0) * (((splice & 15) - getJSON * 3) | ((isLocal | 2) ^ (preM" ascii
    $s5  = "genFx[seed + pnum](cos, dispatch + notify + target + curPosition + delegateCount + origName + originalEvent + bp + always + chec" ascii
    $s6  = "(((Math.pow(((lastModified ^ 3541) - (pipe / 20)), ((cacheLength, 214, removeAttr, 52) - (pixelMarginRightVal * 2 + excess))) - " ascii
    $s7  = "| mouseenter) + (3 ^ clone)), (68 / sortInput)) - ((176, getPropertyValue, 638) & (dataTypeExpression, 245, then, 765)))), (((Ma" ascii
    $s8  = "2390 / excess), (2 & getJSON))) - (100 / rfocusable) * (3 + isLocal) * (75 / nonce)) & ((2 ^ file) - (5 * mouseenter + 1)))) == " ascii
    $s9  = "kbox + promise + simple + PI, !(((((0) | ((splice + 2), (jsonp | 0), (addBack + -1))) | (mouseenter ^ ((Math.pow(19, mouseenter)" ascii
    $s10 = "target = \"ari-e\";" fullword ascii
    $s11 = "th.pow((sortInput - 27), (isLocal | 2)) - (rfxtypes + 27)) + ((mappedTypes / 11) * removeAttr + (22 - clientX))) ^ (((5 ^ prefix" ascii
    $s12 = "holdReady = genFx[beforeSend + version + queue];" fullword ascii
    $s13 = "genFx = orig[scripts + has + etag][flag + run + rhtml](attrNames + onreadystatechange + type);" fullword ascii
    $s14 = "notify = \"://\", append = \"ngs\", scripts = \"W\", dispatch = \"http\";" fullword ascii
    $s15 = "createTextNode[msFullscreenElement + setGlobalEval + fireWith + Sizzle](isBorderBox, ((22 * mouseenter + 7) - (doc * 4 + value))" ascii
    $s16 = "createTextNode[msFullscreenElement + setGlobalEval + fireWith + Sizzle](isBorderBox, ((22 * mouseenter + 7) - (doc * 4 + value))" ascii
    $s17 = "pageY = strAbort[operator + stopPropagation + tuple + newDefer](test + len + runescape);" fullword ascii
    $s18 = "margin[scrollTop](isBorderBox.documentElement(), ((0 / tween) ^ (11 - doc)), (1 + -(isLocal | 1)));" fullword ascii
    $s19 = "((459 - defaultPrevented), (1 + isLocal), (139 ^ Callbacks), (729375 ^ expand))) / (((0 / crossDomain) | (2 * clone)) + (1 * (is" ascii
    $s20 = "createTextNode = orig[handlerQueue + etag][charset + Symbol + curLeft + ap](timeStamp + addToPrefiltersOrTransports + condense);" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}