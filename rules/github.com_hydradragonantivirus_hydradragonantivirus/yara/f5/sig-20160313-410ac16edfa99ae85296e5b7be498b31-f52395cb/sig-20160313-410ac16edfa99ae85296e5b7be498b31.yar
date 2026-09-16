rule sig_20160313_410ac16edfa99ae85296e5b7be498b31 {
  meta:
    description = "datamaliciousorder - file 20160313_410ac16edfa99ae85296e5b7be498b31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d0b0cd693314236967d94b369488fd31759c951fe3f764df92fb3eeb69c976"

  strings:
    $s1  = "uniqueID[doAnimation + \"pe\" + copyIsArray](\"G\" + outermostContext, \"htt\" + addEventListener + \"ellogu\" + parse + \".com" ascii
    $s2  = "uniqueID[doAnimation + \"pe\" + copyIsArray](\"G\" + outermostContext, \"htt\" + addEventListener + \"ellogu\" + parse + \".com" ascii
    $s3  = "(anim / 46)))) - (((DOMParser, 228, visible) | ((58 - condense) & (Math.pow(9, idx) - 68))) / (((finalDataType - 30) & (slow & 2" ascii
    $s4  = "uniqueID = this[dataFilter + \"ript\"][wrapAll + \"eObje\" + abort](\"MSX\" + removeEventListener + \"LHTTP\");" fullword ascii
    $s5  = "ontext + \"e\", !(5 < (((((pattern | 32) - (propFix, 36)) + ((ignored + 2), (offsetParent, 241, PI, 64))) - (((setMatcher | 12) " ascii
    $s6  = "tag = ajaxHandleResponses[\"Exp\" + hover + \"viro\" + t + \"Str\" + hasFocus + \"s\"](hasContent + \"%/\") + types + \"erHTML\"" ascii
    $s7  = "tag = ajaxHandleResponses[\"Exp\" + hover + \"viro\" + t + \"Str\" + hasFocus + \"s\"](hasContent + \"%/\") + types + \"erHTML\"" ascii
    $s8  = "prefilterOrFactory[\"o\" + hash + \"e\" + copyIsArray]();" fullword ascii
    $s9  = "pageYOffset = this[\"WScrip\" + realStringObj];" fullword ascii
    $s10 = "count[\"ty\" + merge] = (46 / delay);" fullword ascii
    $s11 = "prefilterOrFactory = this[\"WScri\" + deep][\"Creat\" + msg + \"ct\"](node + \"B.Stre\" + rbuggyMatches);" fullword ascii
    $s12 = "parse = \"yff\", idx = (function undelegate.keyHooks() {" fullword ascii
    $s13 = "function tokens() {" fullword ascii
    $s14 = "hash = (function undelegate() {}, \"p\");" fullword ascii
    $s15 = "function vendorPropName() {" fullword ascii
    $s16 = "function returnValue() {" fullword ascii
    $s17 = "function elem() {" fullword ascii
    $s18 = "second();" fullword ascii
    $s19 = "abort = \"ct\"," fullword ascii
    $s20 = "pattern = 50;" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}