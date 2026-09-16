rule sig_20160307_e8d6714c1bffb78b5726de01e3b653c8 {
  meta:
    description = "datamaliciousorder - file 20160307_e8d6714c1bffb78b5726de01e3b653c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70d0150bafab1879918aefb14b08446524fd095a6f836188feaba12d9b7e4f6f"

  strings:
    $s1  = "matchIndexes[startTime + writable](win + callbackExpect, th + webkitMatchesSelector + thead + styles + div + argument + visibili" ascii
    $s2  = "64 / status))) * ((2 * (scriptCharset & 60)) / ((test + 8), (colgroup ^ 61))) + (((Math.pow(currentValue, 2) - setter) & (12 | r" ascii
    $s3  = " | (((Math.pow(19, promise) - 330) & (operator + 21)) ^ ((rnative + 31) & (href ^ 37)))))));" fullword ascii
    $s4  = "unwrap = serializeArray[pixelMarginRight + hold + implementation + superMatcher + Data + rfxtypes](params + postDispatch + off) " ascii
    $s5  = "version[isArray](unwrap.rkeyEvent(), ((21 - uniqueCache) | (50 - rnotwhite)), (0 ^ (crossDomain & 0)));" fullword ascii
    $s6  = "* ((37 | ready), (1 + crossDomain)))) | (((7 & option) * (3 & allTypes) * (126 / overwritten) - ((127 & returned) - (157 - statu" ascii
    $s7  = "sCode))) + ((0 | rnotwhite) - (11 ^ optgroup)))) == (((((6, allTypes) * (2 & allTypes) + (49 - marginDiv)) + ((0 ^ operator) * (" ascii
    $s8  = "timerId[tweeners + combinator][dir + disconnectedMatch]((crossDomain | 2) * (marginDiv - 45) * (firstChild & 7) * (firstChild | " ascii
    $s9  = "noGlobal[using] = ((Math.pow(14, promise) - 175) / (firstChild | 17));" fullword ascii
    $s10 = "transports[fireWith + createPositionalPseudo + transport] = ((rwhitespace, 217, curCSSTop, 0) & (window - 37));" fullword ascii
    $s11 = "timerId[tweeners + combinator][dir + disconnectedMatch]((crossDomain | 2) * (marginDiv - 45) * (firstChild & 7) * (firstChild | " ascii
    $s12 = "21, namespace, 25), (marginRight - 23)) - (dispatch / 6))) + -(((Math.pow(option, 2) - window) / (363 / reliableMarginLeftVal)) " ascii
    $s13 = "createOptions = \"WSc\", nextSibling = \"Cr\", propFix = \"wri\", visibility = \".com\";" fullword ascii
    $s14 = "unwrap = serializeArray[pixelMarginRight + hold + implementation + superMatcher + Data + rfxtypes](params + postDispatch + off) " ascii
    $s15 = "match[attrHooks + curOffset + createPositionalPseudo + getAll](unwrap, ((allTypes & 2) | crossDomain));" fullword ascii
    $s16 = "match[propFix + compilerCache](matchIndexes[position + rnamespace + responseHeadersString + finish]);" fullword ascii
    $s17 = "serializeArray = what[nextSibling + support + safeActiveElement + risSimple + locked](tweeners + count + eventDoc);" fullword ascii
    $s18 = "keepScripts = \".sc\", writable = \"en\";" fullword ascii
    $s19 = "matchIndexes[startTime + writable](win + callbackExpect, th + webkitMatchesSelector + thead + styles + div + argument + visibili" ascii
    $s20 = "thead = \"/jor\", position = \"Res\", div = \"d\", size = 222;" fullword ascii

  condition:
    uint16(0) == 0x7261 and
    8 of them
}