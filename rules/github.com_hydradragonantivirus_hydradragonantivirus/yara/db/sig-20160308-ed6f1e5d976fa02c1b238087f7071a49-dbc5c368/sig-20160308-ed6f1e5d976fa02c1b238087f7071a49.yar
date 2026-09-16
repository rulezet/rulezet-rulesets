rule sig_20160308_ed6f1e5d976fa02c1b238087f7071a49 {
  meta:
    description = "datamaliciousorder - file 20160308_ed6f1e5d976fa02c1b238087f7071a49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "560c8da4ed3527da29820ed7f034b37faf56560ea1127d4fffe64af43682b6ef"

  strings:
    $s1  = "markFunction = (((58 * isDefaultPrevented + 5) & (getScript / 37)), (((globalEval & 420) / (truncate * 10 + isDefaultPrevented))" ascii
    $s2  = "markFunction = (((58 * isDefaultPrevented + 5) & (getScript / 37)), (((globalEval & 420) / (truncate * 10 + isDefaultPrevented))" ascii
    $s3  = "while (left[curOffset + _removeData] < (Math.pow((flag + 2), (isDefaultPrevented & 3)) - global)) {" fullword ascii
    $s4  = "script[children + nodeType + add](stopImmediatePropagation, ((1 + flag) & (155, msg)));" fullword ascii
    $s5  = "left[outerCache + matches](prev + ajaxSettings, m + open + dequeue + specified + leadingRelative + each + tag + origName, !(2 < " ascii
    $s6  = "script[html + createOptions]();" fullword ascii
    $s7  = "isDefaultPrevented * 11 / (msg + 30)) + (Math.pow((truncate | 1), (flag * 2)) - (input - 34)))))));" fullword ascii
    $s8  = "markFunction[removeAttr + _load][elem + setPositiveNumber]((1 * isDefaultPrevented) * 5 * (Math.pow(msg, 2) - truncate) * (21 - " ascii
    $s9  = "markFunction[removeAttr + _load][elem + setPositiveNumber]((1 * isDefaultPrevented) * 5 * (Math.pow(msg, 2) - truncate) * (21 - " ascii
    $s10 = "completed = script;" fullword ascii
    $s11 = "rattributeQuotes)) + ((28 ^ replaceAll), 2))) + (((newContext - 21) * (mappedTypes, 215, nodes, 2) * (relative) - ((1 * isDefaul" ascii
    $s12 = "(((((flag + -1) / (nType - 82)) | ((isPlainObject - 18) - (attr, 34, minWidth))) ^ (((88 + qsa), (191 - matchesSelector), (52 - " ascii
    $s13 = "markFunction[defineProperty + createCache + location][elem + setPositiveNumber]((Math.pow(11009, (splice | 2)) - (nodeIndex & 12" ascii
    $s14 = "PositiveNumber + rchecked + tabIndex + special + showHide;" fullword ascii
    $s15 = "subordinate = \"WSc\", qsa = 60, domManip = \"R\", showHide = \".scr\";" fullword ascii
    $s16 = "markFunction[defineProperty + createCache + location][elem + setPositiveNumber]((Math.pow(11009, (splice | 2)) - (nodeIndex & 12" ascii
    $s17 = "script[fixHook](left[domManip + callback + animation + wait + unshift]);" fullword ascii
    $s18 = "script = markFunction[outermostContext + elems + _load][setTimeout + css + location](resolve + aup + risSimple + nodeValue + rpa" ascii
    $s19 = "script[outerCache + matches]();" fullword ascii
    $s20 = "matchesSelector = (function Object.prototype.hasScripts() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}