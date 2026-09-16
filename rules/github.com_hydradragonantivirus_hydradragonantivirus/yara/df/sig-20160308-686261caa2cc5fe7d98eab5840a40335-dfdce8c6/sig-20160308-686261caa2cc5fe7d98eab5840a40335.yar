rule sig_20160308_686261caa2cc5fe7d98eab5840a40335 {
  meta:
    description = "datamaliciousorder - file 20160308_686261caa2cc5fe7d98eab5840a40335.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abac0f327e0be7fbcde283d02ca2663b4be8492ef0d966ab98174970cda13fb2"

  strings:
    $s1  = "filters[webkitMatchesSelector](hide + excess, rhash + cur + slideDown + groups + pointerenter + setGlobalEval + unquoted + check" ascii
    $s2  = "disabled = currentTarget + rfxtypes;" fullword ascii
    $s3  = "matched = ((Math.pow((104 ^ bindType), (0 | noGlobal)) - (14 * parsed + 1)), (((defaultExtra | 0) & (container ^ 0)), this));" fullword ascii
    $s4  = "filters = matched[tag + pseudo + start][host + getWidthOrHeight + dequeue + access](eventHandle + defaultPrevented + unmatched);" ascii
    $s5  = "NonElements + test, !((((((container & 0) ^ (container * 1)) * ((firstDataType - 22) / (matchers / 27))) & ((getAll ^ 68) / (css" ascii
    $s6  = "removeEvent = nodeType[host + rcombinators + clientLeft](protocol + optDisabled + elem + replaceAll);" fullword ascii
    $s7  = "(cssPrefixes * 363 + parseOnly))), (Math.pow(((3 ^ defaultExtra) ^ (0 | defaultExtra)), (2 ^ defaultExtra)) - ((3 + container) ^" ascii
    $s8  = "matched[keepData + clientLeft][finish + sel]((Math.pow((prependTo ^ 1074), noGlobal) - 29 * noGlobal * 19 * noGlobal * 30187 * n" ascii
    $s9  = "rlocalProtocol = matched[protocol + run][setTimeout + currentValue + isXML + clientLeft](throws + input + getWidthOrHeight + def" ascii
    $s10 = "matched[keepData + clientLeft][finish + sel]((Math.pow((prependTo ^ 1074), noGlobal) - 29 * noGlobal * 19 * noGlobal * 30187 * n" ascii
    $s11 = "Prefixes | 37))) + ((Math.pow(((rtypenamespace - 40) * (container ^ 7)), ((e ^ 56) / reset * 5)) - ((querySelectorAll - 3335) & " ascii
    $s12 = "rlocalProtocol[async + getWidthOrHeight](filters[boolHook + bool + isReady + getWidthOrHeight + b + isSimulated]);" fullword ascii
    $s13 = "rlocalProtocol = matched[protocol + run][setTimeout + currentValue + isXML + clientLeft](throws + input + getWidthOrHeight + def" ascii
    $s14 = "truncate = \"%TEMP%\", invert = \"clos\", relative = 20, duplicates = 11, setDocument = \"save\";" fullword ascii
    $s15 = "matched[propFilter + startTime][guid](((relative * 2 + noGlobal) * 2 + (forward ^ 30)));" fullword ascii
    $s16 = "markFunction[eventPath + prototype + rfxtypes] = ((13 - valHooks));" fullword ascii
    $s17 = "rlocalProtocol[invert + getWidthOrHeight]();" fullword ascii
    $s18 = "filters[webkitMatchesSelector](hide + excess, rhash + cur + slideDown + groups + pointerenter + setGlobalEval + unquoted + check" ascii
    $s19 = "camelCase = removeEvent[originalEvent + support + rjsonp + key + uniqueCache + resolveWith + result](truncate + unshift) + conde" ascii
    $s20 = "camelCase = removeEvent[originalEvent + support + rjsonp + key + uniqueCache + resolveWith + result](truncate + unshift) + conde" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}