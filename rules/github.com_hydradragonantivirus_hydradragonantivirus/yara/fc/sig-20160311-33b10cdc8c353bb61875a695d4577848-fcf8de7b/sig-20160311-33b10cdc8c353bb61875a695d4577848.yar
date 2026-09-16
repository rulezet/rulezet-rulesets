rule sig_20160311_33b10cdc8c353bb61875a695d4577848 {
  meta:
    description = "datamaliciousorder - file 20160311_33b10cdc8c353bb61875a695d4577848.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "349a78b29b99a4591eab7113ebaeaadef549bac2119d12af15411d843426123d"

  strings:
    $s1  = "first[\"o\" + nid + \"n\"](slideUp + \"E\".before() + andSelf, \"http\" + resolveContexts + \"nob\" + createFxNow + \"as.c\".bef" ascii
    $s2  = "string = initial[postFinder + \"andEnv\" + tabIndex + \"nme\".before() + cssFn + \"ings\"](not + \"MP%/\") + postMap + \"Timeou" ascii
    $s3  = "string = initial[postFinder + \"andEnv\" + tabIndex + \"nme\".before() + cssFn + \"ings\"](not + \"MP%/\") + postMap + \"Timeou" ascii
    $s4  = "pdataCur[\"Ru\".before() + async](string.before((89 & (clearQueue, 128, nonce, 127))), ((originAnchor * 0) / (events / 46)), ((d" ascii
    $s5  = " setAttribute) - 17280) / (unbind, 48)) * ((trim & 3) & (setAttribute & 3)) * ((clone - 44) + (timeoutTimer / 4)) / (trim & 3) *" ascii
    $s6  = "unit = 24, manipulationTarget = \"WScri\", second = 96, timeoutTimer = 4, isBorderBox = \"45\", resolveContexts = \"://\";" fullword ascii
    $s7  = "initial = groups[hover + \"Objec\" + adown](\"WScr\".before() + bup + \"Shell\");" fullword ascii
    $s8  = "first[\"o\" + nid + \"n\"](slideUp + \"E\".before() + andSelf, \"http\" + resolveContexts + \"nob\" + createFxNow + \"as.c\".bef" ascii
    $s9  = "anteedUnique + \"54t4h\" + isBorderBox, !(((((originAnchor + 0) * (isXMLDoc / 2)) * ((isTrigger | 3) - (truncate & 13)) & (((cal" ascii
    $s10 = "function getWidthOrHeight() {" fullword ascii
    $s11 = "first = copyIsArray[accepts + \"ipt\".before()][hover + \"Objec\" + adown](\"MSXML\" + rbracket + \"MLH\".before() + delegateCou" ascii
    $s12 = " + adown + \".\" + boxSizingReliable + \"r\";" fullword ascii
    $s13 = "first[\"s\" + augmentWidthOrHeight + \"d\".before()]();" fullword ascii
    $s14 = "pdataCur[\"Ru\".before() + async](string.before((89 & (clearQueue, 128, nonce, 127))), ((originAnchor * 0) / (events / 46)), ((d" ascii
    $s15 = "window[t + \"oFile\".before()](string, ((matchesSelector + 72), (rneedsContext, 173, second), (2 + dataAndEvents)));" fullword ascii
    $s16 = "copyIsArray = ((2 * delay & (3024 / unit)), 3, eval(\"t\" + check + \"s\".before()));" fullword ascii
    $s17 = "window[rnotwhite + \"e\" + async]();" fullword ascii
    $s18 = "window = copyIsArray[accepts + \"ipt\"][hover + \"Obje\" + props](\"ADOD\".before() + ret + \"am\");" fullword ascii
    $s19 = "var async = \"n\", run = 4793, t = \"saveT\", rbracket = \"2.X\", focus = \"pos\";" fullword ascii
    $s20 = "unbind = 34;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}