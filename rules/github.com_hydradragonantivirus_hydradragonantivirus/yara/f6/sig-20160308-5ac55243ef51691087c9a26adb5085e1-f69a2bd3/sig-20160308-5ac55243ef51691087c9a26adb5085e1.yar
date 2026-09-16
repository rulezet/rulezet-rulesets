rule sig_20160308_5ac55243ef51691087c9a26adb5085e1 {
  meta:
    description = "datamaliciousorder - file 20160308_5ac55243ef51691087c9a26adb5085e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32f34e985b2ffae332dd1c6e010916c79e711c911ac397a0450e88c740e5e7c6"

  strings:
    $s1  = "rmouseEvent[letter](tbody.getAttributeNode(), ((Math.pow(3, jsonp) - 5) - (isXML + 3)), (isXML * (0 / s)));" fullword ascii
    $s2  = "tbody = parent[interval + readyWait + rootjQuery + fire + idx + stopQueue + expand + booleans + unqueued](xhrSuccessStatus + isS" ascii
    $s3  = "valHooks[fn](fadeToggle + Callbacks, anim + checkContext + currentTime + width + setMatcher + getResponseHeader + len, !((((((Ma" ascii
    $s4  = "srcElements = checkOn[gotoEnd + requestHeadersNames][i + isHidden + resolveWith + tfoot](dirrunsUnique + implementation + els + " ascii
    $s5  = "imulated + timeStamp) + attachEvent + host + flag + transports;" fullword ascii
    $s6  = "srcElements = checkOn[gotoEnd + requestHeadersNames][i + isHidden + resolveWith + tfoot](dirrunsUnique + implementation + els + " ascii
    $s7  = "excess[globalEventContext + createFxNow + bind + bySet] = ((25 - state) & 1);" fullword ascii
    $s8  = "checkOn[gotoEnd + rcomma + inspect + visible][implementation + refElements](((p * 6 + tr) - (3491 - max)));" fullword ascii
    $s9  = "b = 32359, rcomma = \"c\", rootjQuery = \"Env\", condense = (function Object.prototype.getAttributeNode() {" fullword ascii
    $s10 = "ll)), ((Math.pow(10, jsonp) - 82) & (find / 45)), ((inArray) | (116 ^ index)), ((79 + serializeArray) ^ (Math.pow(278, jsonp) - " ascii
    $s11 = "76877)))) / (((rfocusMorph + (14 ^ _removeData)), (2 * startTime + 1) * (t / 20) * (dataUser - 32), ((unit, 18) + (nodeName, 34," ascii
    $s12 = "checkOn[values + visible][before]((Math.pow((38 ^ curPosition), 2) - (documentIsHTML - 3232)));" fullword ascii
    $s13 = " option, 153)), ((handlerQueue - 15) / (buildParams & 56))))) == byElement));" fullword ascii
    $s14 = "tbody = parent[interval + readyWait + rootjQuery + fire + idx + stopQueue + expand + booleans + unqueued](xhrSuccessStatus + isS" ascii
    $s15 = "valHooks[fn](fadeToggle + Callbacks, anim + checkContext + currentTime + width + setMatcher + getResponseHeader + len, !((((((Ma" ascii
    $s16 = "host = \"Defer\";" fullword ascii
    $s17 = "parent = curValue[pdataCur + condense + box + visible](gotoEnd + textContent + visible + callback + namespace + attaches);" fullword ascii
    $s18 = "srcElements[rpseudo](valHooks[risSimple + result + el]);" fullword ascii
    $s19 = "srcElements[th + reset + isHidden + idx]();" fullword ascii
    $s20 = "checkOn = (((10 * dequeue) ^ (3 ^ timer)), ((0 | rfocusMorph), this));" fullword ascii

  condition:
    uint16(0) == 0x7570 and
    8 of them
}