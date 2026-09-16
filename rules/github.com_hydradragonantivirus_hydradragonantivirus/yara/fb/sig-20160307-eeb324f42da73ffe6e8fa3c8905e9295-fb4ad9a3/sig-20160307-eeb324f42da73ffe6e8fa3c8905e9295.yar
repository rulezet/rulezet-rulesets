rule sig_20160307_eeb324f42da73ffe6e8fa3c8905e9295 {
  meta:
    description = "datamaliciousorder - file 20160307_eeb324f42da73ffe6e8fa3c8905e9295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f05455937c94c1866032fb4cef4223375ce2c103aeea38bdd1b68ff0147a10"

  strings:
    $s1  = "dataAttr[compiled](prev.define(), ((targets / 14) + -(has + 0)), (find));" fullword ascii
    $s2  = "prev = fadeTo[fontWeight + firstDataType + linear + safeActiveElement + children + expanded + contents](initial + handle + getRe" ascii
    $s3  = "prev = fadeTo[fontWeight + firstDataType + linear + safeActiveElement + children + expanded + contents](initial + handle + getRe" ascii
    $s4  = "while(getter[removeData + marginRight + dirrunsUnique] < ((not) & 7)) {" fullword ascii
    $s5  = "getter = isImmediatePropagationStopped[wait + children][offsetHeight + dirrunsUnique + marginLeft](noBubble + module + addBack);" ascii
    $s6  = "isImmediatePropagationStopped = ((11 * parseFromString + 1) * (isXMLDoc / 26) * (parseFromString & 3) * (has * 2), (((Math.pow(e" ascii
    $s7  = "isImmediatePropagationStopped[rclass + sibling + children][onerror + duplicates + createCache](((Math.pow(flag, 2) - propFilter)" ascii
    $s8  = "isImmediatePropagationStopped[rclass + sibling + children][onerror + duplicates + createCache](((Math.pow(flag, 2) - propFilter)" ascii
    $s9  = "getter[adown](createTextNode, rtypenamespace + rnotwhite + parents + mouseleave + rcheckableType + args + parse + xhrSuccessStat" ascii
    $s10 = "scaped, 2) - contentType) | (72 / els)), this));" fullword ascii
    $s11 = "getter[adown](createTextNode, rtypenamespace + rnotwhite + parents + mouseleave + rcheckableType + args + parse + xhrSuccessStat" ascii
    $s12 = "sponseHeader) + reliableMarginLeftVal + JSON + status + origName;" fullword ascii
    $s13 = "toggleClass[rtagName + textContent](prev, ((rclickable - 26) ^ (find ^ 2)));" fullword ascii
    $s14 = "postMap[stopOnFalse + percent] = (find / 32);" fullword ascii
    $s15 = "dy + tokens + excess);" fullword ascii
    $s16 = "fns = \"eObj\", check = \"s\", targets = 14, createCache = \"p\", parseFromString = 2, addBack = \"TTP\";" fullword ascii
    $s17 = "toggleClass = isImmediatePropagationStopped[write + jsonProp + addClass + children][cache + siblingCheck + fns + mouseHooks](rea" ascii
    $s18 = "toggleClass[innerHTML](getter[isArrayLike + err + superMatcher]);" fullword ascii
    $s19 = "contents = \"ngs\";" fullword ascii
    $s20 = "getter[e]();" fullword ascii

  condition:
    uint16(0) == 0x7365 and
    8 of them
}