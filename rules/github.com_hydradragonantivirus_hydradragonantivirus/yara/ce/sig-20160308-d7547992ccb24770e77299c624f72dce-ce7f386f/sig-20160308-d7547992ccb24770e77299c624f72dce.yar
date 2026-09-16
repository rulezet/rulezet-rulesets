rule sig_20160308_d7547992ccb24770e77299c624f72dce {
  meta:
    description = "datamaliciousorder - file 20160308_d7547992ccb24770e77299c624f72dce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d979b1976c9dc350b11ae6f3618ac3388fed55af0fd9046c52fdf8f4fd9a4f64"

  strings:
    $x1  = "bool[j + noBubble](box, removeClass + visibility + configurable + copy + suffix + keyCode + rsingleTag + mapped + button + callb" ascii
    $s2  = "2)) - (body * 2 + to)), ((36, compare, 1) ^ (getScript & 3))) - ((idx / 33) - (timers & 347))), (((matcherIn + 1) ^ (startLength" ascii
    $s3  = "bool[rheaders + processData]();" fullword ascii
    $s4  = "support[setDocument + define + firstChild + pdataCur + setAttribute][removeEventListener + currentTime](((Math.pow(val, 2) - get" ascii
    $s5  = "support[setDocument + define + firstChild + pdataCur + setAttribute][removeEventListener + currentTime](((Math.pow(val, 2) - get" ascii
    $s6  = "1))) - ((flag | 522) ^ (radio ^ 835))) * ((getScript & 2) & (getScript - 0))), ((Math.pow((Math.pow((hasDuplicate - 1), (push | " ascii
    $s7  = "rFields), (74 & splice), 8), ((hold, 183, postFilter) ^ (87 & ajaxSetup)), ((46 - readyState) | (124 & destElements)), ((1 * pus" ascii
    $s8  = "restoreScript = realStringObj[location + tokenCache + combinator + fail + tokenCache](pattern + updateFunc + mimeType);" fullword ascii
    $s9  = "disable = restoreScript[parent + scrollTo + setFilters + matcher + prefilterOrFactory + headers + condense](one + list + animati" ascii
    $s10 = "bool = support[prev + clearTimeout][unbind + unique + onabort + udataCur](getById + fix + start + compareDocumentPosition);" fullword ascii
    $s11 = "- 16)), ((pointerleave - 88) & (activeElement & 255)), ((createTextNode + 15) / (rlocalProtocol & 31))) ^ (((temp, 270)) / ((dis" ascii
    $s12 = "support = ((Math.pow((25 * matcherIn + 15), (push | 2)) - (fragment / 45)), (((push ^ 8) | (push | 0)), this));" fullword ascii
    $s13 = "rkeyEvent = \"ition\", fixInput = \"a\", once = 42, thead = \"Sle\", disconnectedMatch = 12;" fullword ascii
    $s14 = "container[rquickExpr + rkeyEvent] = ((1 + push) + -(45, isLocal, 1));" fullword ascii
    $s15 = " & 7)) | ((push | 1) ^ (prevObject & 0))))) == ((Math.pow(((Math.pow((maxWidth ^ 110), matcherIn) - (10429 ^ setup)), ((127 - ex" ascii
    $s16 = "while (bool[msFullscreenElement + code + shift] < ((6 - matcherIn) & (Math.pow(4, matcherIn) - 9))) {" fullword ascii
    $s17 = "disable = restoreScript[parent + scrollTo + setFilters + matcher + prefilterOrFactory + headers + condense](one + list + animati" ascii
    $s18 = "support[slideUp + hasOwnProperty + dataType + tokenCache][thead + shift + hooks](((hover / 35) | (timeStamp * 57 + hookFn)));" fullword ascii
    $s19 = "qualifier[ajaxTransport + propFilter + shift](disable, ((matcherFromTokens, 1) * (matcherIn | 0)));" fullword ascii
    $s20 = "cess) / (124, td, 195, isWindow))), (((1 * prevObject) + (1 * prevObject)) + (0 / checkClone))) - (((51 + prevObject), (129 + xh" ascii

  condition:
    uint16(0) == 0x6974 and
    1 of ($x*) and 4 of them
}