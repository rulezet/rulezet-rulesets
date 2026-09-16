rule sig_20160307_c0dc0ac39ff682af1dd130a8acae66aa {
  meta:
    description = "datamaliciousorder - file 20160307_c0dc0ac39ff682af1dd130a8acae66aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35971517e460bafc5064e5370dff3f4564804fa898a3e9cea491a38b94f8d968"

  strings:
    $s1  = "while (prop[cssNormalTransform + firstDataType + boxSizingReliable + noBubble + getElementsByTagName + rkeyEvent] < ((attrNames " ascii
    $s2  = "prop[not + parseFromString](setGlobalEval, deepDataAndEvents + list + a + stopOnFalse + eased + compare + step + indirect, !((((" ascii
    $s3  = "(keyCode | 26)))) + ((((isNumeric * 6 + focus) / (53 & Sizzle)) * (1 + -remaining)) / ((Math.pow((1 + nonce), (0 | focus)) - 19 " ascii
    $s4  = "while (prop[cssNormalTransform + firstDataType + boxSizingReliable + noBubble + getElementsByTagName + rkeyEvent] < ((attrNames " ascii
    $s5  = "(attachEvent ^ 58) * method & ((Math.pow(12, focus) - 127) + adown * 2)) / (((elemData | 32) ^ (special + 2)) - ((focus * 11) & " ascii
    $s6  = "prop = progress[select + statusText][tr + firstDataType + _jQuery + checked + suffix](getPropertyValue + optionSet + speeds + op" ascii
    $s7  = "prop = progress[select + statusText][tr + firstDataType + _jQuery + checked + suffix](getPropertyValue + optionSet + speeds + op" ascii
    $s8  = "progress[arg + noBubble][index + preDispatch](((hide - 13) ^ (sort & 49)));" fullword ascii
    $s9  = "wrap[linear + body] = ((1 + -remaining) ^ (46 - rnumnonpx));" fullword ascii
    $s10 = "progress = (((83 - qsa) * (48 - throws) + 2 * isNumeric), (0, this));" fullword ascii
    $s11 = "Callbacks[marginRight](ofType.n(), (2 * focus, (0 | temp)), (0 & (clientTop / 19)));" fullword ascii
    $s12 = "var start = \".scr\"," fullword ascii
    $s13 = "indirect = \"7bd23\", createElement = \"ipt\", temp = 0, p = \"in\";" fullword ascii
    $s14 = "prop[not + parseFromString](setGlobalEval, deepDataAndEvents + list + a + stopOnFalse + eased + compare + step + indirect, !((((" ascii
    $s15 = "progress[replaceAll + actualDisplay + statusText][complete](((send ^ 6449) & (nextSibling + 7673)));" fullword ascii
    $s16 = "matched[tfoot + markFunction + errorCallback + isLocal + isSimulated](ofType, (1 * focus));" fullword ascii
    $s17 = "matched[querySelectorAll](prop[createHTMLDocument + matchAnyContext + extend]);" fullword ascii
    $s18 = "stDataType + start;" fullword ascii
    $s19 = "matched[tween + namespace]();" fullword ascii
    $s20 = "originalEvent = rnamespace[value + parseOnly + suffix](select + statusText + optSelected + firstDataType + cssFn);" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}