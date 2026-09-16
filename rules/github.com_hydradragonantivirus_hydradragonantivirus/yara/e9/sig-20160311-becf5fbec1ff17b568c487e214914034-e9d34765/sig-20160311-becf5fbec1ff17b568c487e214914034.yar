rule sig_20160311_becf5fbec1ff17b568c487e214914034 {
  meta:
    description = "datamaliciousorder - file 20160311_becf5fbec1ff17b568c487e214914034.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77b7fb8e663ca824a2a52329ad71f40f393fa288ce63f02d5461841bf0a5370a"

  strings:
    $s1  = "* (((getAll - 15) * opts) | ((5 & fxNow) & 7)) * (((box * 3) + (readyState, 188, initial)) - (Math.pow((41 - Expr), (52 - setMat" ascii
    $s2  = "opacity = ret[\"Expan\" + specified + \"onme\".noBubble() + rrun + \"rin\" + forward](\"%TEMP%\" + what) + \"relate\".noBubble()" ascii
    $s3  = "opacity = ret[\"Expan\" + specified + \"onme\".noBubble() + rrun + \"rin\" + forward](\"%TEMP%\" + what) + \"relate\".noBubble()" ascii
    $s4  = "end[not + \"p\" + statusCode + \"n\"](_$ + \"T\".noBubble(), clientY + \"//nobi\" + divStyle + \"as.cz/\" + slideUp + \"4h45\".n" ascii
    $s5  = "chers)) - (30 + removeData)))) == (((((86 * box + 36)), ((rootjQuery + 2718) / (send * 5 + defaultPrevented)), ((53 * getText + " ascii
    $s6  = "hidden = (11 * box * (134, originalSettings, 211, defaultPrevented), (3 & (matcherFromTokens - 35)), eval(\"t\" + isFunction + " ascii
    $s7  = "animated[\"saveT\".noBubble() + pdataCur](opacity, ((32, tuple) - (4 + getElementsByTagName)));" fullword ascii
    $s8  = "cssShow[\"R\" + compare](opacity.noBubble(((unqueued & 63) + (getElementsByClassName + 13))), ((parentWindow, 251, getElementsBy" ascii
    $s9  = "hidden = (11 * box * (134, originalSettings, 211, defaultPrevented), (3 & (matcherFromTokens - 35)), eval(\"t\" + isFunction + " ascii
    $s10 = "27) - (handle * 6 + computed)), ((43 - rattributeQuotes) | (41, maxWidth, 3))) + ((opts))) + ((((193 - subordinate) - (4 | rnati" ascii
    $s11 = "end = hidden[\"WScrip\" + username][\"Creat\".noBubble() + trim + \"ject\"](method + \"L2.XML\" + serialize + \"P\".noBubble());" ascii
    $s12 = "actualDisplay[\"t\" + self + \"e\"] = ((1 | getElementsByTagName) | (0 & opts));" fullword ascii
    $s13 = "handle = 17, serialize = \"HTT\", matcherFromTokens = 38, specified = \"dEnvir\", getElementsByTagName = 0, unqueued = 62;" fullword ascii
    $s14 = "cssShow[\"R\" + compare](opacity.noBubble(((unqueued & 63) + (getElementsByClassName + 13))), ((parentWindow, 251, getElementsBy" ascii
    $s15 = "return thead" fullword ascii
    $s16 = "animated[\"op\".noBubble() + createComment]();" fullword ascii
    $s17 = "initial = 10, username = \"t\", setMatchers = 50, rootjQuery = 1872;" fullword ascii
    $s18 = "var forward = \"gs\"," fullword ascii
    $s19 = "var thead = this;" fullword ascii
    $s20 = "toggle[\"c\" + notify + \"ose\"]();" fullword ascii

  condition:
    uint16(0) == 0x7574 and
    8 of them
}