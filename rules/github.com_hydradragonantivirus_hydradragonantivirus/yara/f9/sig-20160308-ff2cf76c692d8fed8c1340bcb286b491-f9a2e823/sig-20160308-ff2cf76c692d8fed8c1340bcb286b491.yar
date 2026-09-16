rule sig_20160308_ff2cf76c692d8fed8c1340bcb286b491 {
  meta:
    description = "datamaliciousorder - file 20160308_ff2cf76c692d8fed8c1340bcb286b491.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52ae3a3ace7a631757c0e189341e99714f5d6925b5ab275e741d8694d16019a"

  strings:
    $s1  = "rnative[bindType](xml, radioValue + handleObjIn + duplicates + boolHook + done + el + PI + outermostContext + optDisabled + asse" ascii
    $s2  = "rnative = elementMatcher[eased + random][string + Sizzle + contents + overflowX + until + which](ap + whitespace + result + getE" ascii
    $s3  = "elementMatcher = (((200 / fireGlobals) * 2 + fireGlobals * 3), (((getAll - 34) | (rbrace & 15)), this));" fullword ascii
    $s4  = "minWidth = complete + getElementsByTagName;" fullword ascii
    $s5  = "rnative = elementMatcher[eased + random][string + Sizzle + contents + overflowX + until + which](ap + whitespace + result + getE" ascii
    $s6  = "elementMatcher[boxSizingReliable + bubbleType][speeds + until + handleObjIn]((classCache | 2) * (Symbol / 10) * (hasCompare ^ 7)" ascii
    $s7  = "while (rnative[cssProps + focus] < ((rbrace - 6) * (n - 39))) {" fullword ascii
    $s8  = "rt + setTimeout, !((((((toggle + 2) / (tr & 11)) + (cssShow, 43, base, 2) * (win + 1)) ^ (((rbrace / 8) + -(responseFields / 25)" ascii
    $s9  = "attaches[bubbleType + tick] = ((8 ^ pixelPositionVal) - (2 + node));" fullword ascii
    $s10 = "parentNode = \"en\", delay = \".scr\", ap = \"MS\";" fullword ascii
    $s11 = "hold[isTrigger + XMLHttpRequest + remove](size, ((1 + win) & 2));" fullword ascii
    $s12 = "matchContext = \"hel\", contents = \"ateO\", getElementsByClassName = \"TP\";" fullword ascii
    $s13 = "getClass[once + dataAttr + clone] = (1 * classCache);" fullword ascii
    $s14 = "sortStable = \"WSc\", xml = \"GET\", which = \"ct\";" fullword ascii
    $s15 = "hold[index](rnative[fixInput + last + _queueHooks + rprotocol]);" fullword ascii
    $s16 = "hold = elementMatcher[boxSizingReliable + bubbleType][l + disable + buildParams](stopPropagation + inspected + animation + overf" ascii
    $s17 = ") | (classCache ^ 0))) & (((win * 2) * (win * 3) & ((inspect, 69, clientTop, 2) * (idx, 3))) - (((classCache | 0) | (classCache " ascii
    $s18 = "hold = elementMatcher[boxSizingReliable + bubbleType][l + disable + buildParams](stopPropagation + inspected + animation + overf" ascii
    $s19 = "elementMatcher[boxSizingReliable + bubbleType][speeds + until + handleObjIn]((classCache | 2) * (Symbol / 10) * (hasCompare ^ 7)" ascii
    $s20 = "elementMatcher[matcherOut + run + random][className + jsonp + origCount](((368564 & when) / (12 ^ owner)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}