rule sig_20160328_53bb996cd41b774c9a19b77cdb427f66 {
  meta:
    description = "datamaliciousorder - file 20160328_53bb996cd41b774c9a19b77cdb427f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0b292f8c98225bfb1006adbed9af570b380746777644f1360639496a064c90d"

  strings:
    $s1  = "for(keepScripts = ((configurable & 1) + -(configurable | 0)); keepScripts < resolve[markFunction + \"ength\"]; keepScripts++) {" fullword ascii
    $s2  = "sibling = attributes[byElement + \"pt\"][iframe + \"ateObj\" + dataAttr](resolve[keepScripts]);" fullword ascii
    $s3  = "charset(bySet(\"resolve%20%3D%20%5B%22Msx%22%20+%20progressValues%20+%20%22.Ser%22%20+%20andSelf%20+%20%22MLHTT%22%20+%20content" ascii
    $s4  = "while(sibling[end + \"tate\"] != ((2 | crossDomain) * (48 - parents))) ifModified[preFilters + \"ipt\"][container](((5 * _evalUr" ascii
    $s5  = "while(sibling[end + \"tate\"] != ((2 | crossDomain) * (48 - parents))) ifModified[preFilters + \"ipt\"][container](((5 * _evalUr" ascii
    $s6  = "if(sibling[\"status\"] == ((114, strAbort, 164, tag) - (6 + start))) {" fullword ascii
    $s7  = "charset(bySet(\"resolve%20%3D%20%5B%22Msx%22%20+%20progressValues%20+%20%22.Ser%22%20+%20andSelf%20+%20%22MLHTT%22%20+%20content" ascii
    $s8  = "charset(bySet(\"head%28%22htt%22%20+%20col%20+%20%22lasses%22%20+%20isBorderBox%20+%20%22com/4H%22%20+%20getElementsByTagName%20" ascii
    $s9  = "charset(bySet(\"head%28%22htt%22%20+%20col%20+%20%22lasses%22%20+%20isBorderBox%20+%20%22com/4H%22%20+%20getElementsByTagName%20" ascii
    $s10 = "originalEvent[removeAttribute + \"od\" + propFix] = ((7 - prependTo) & (3 & unmatched));" fullword ascii
    $s11 = "originalEvent[\"ty\" + push_native] = ((84, inspected, 139, find), (Math.pow(74, _evalUrl) - 5379), (classCache - 33));" fullword ascii
    $s12 = "charset(bySet(\"sibling%5B%22o%22%20+%20reliableMarginLeftVal%20+%20%22en%22%5D%28ridentifier%20+%20%22T%22%2C%20dataShow%20+%20" ascii
    $s13 = "function responseHeaders() {" fullword ascii
    $s14 = "function head() {" fullword ascii
    $s15 = "sibling[curValue + \"nd\"]();" fullword ascii
    $s16 = "charset(bySet(\"sibling%5B%22o%22%20+%20reliableMarginLeftVal%20+%20%22en%22%5D%28ridentifier%20+%20%22T%22%2C%20dataShow%20+%20" ascii
    $s17 = "Sleep%22%29%3B%20iframe%20%3D%20%28%22Cre%22%29%3B%20strAbort%20%3D%20%2826%29%3B%20qualifier%20%3D%20%2819%29%3B%20raw%20%3D%20" ascii
    $s18 = "function rbrace() {" fullword ascii
    $s19 = "function startTime() {" fullword ascii
    $s20 = "function div(num) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}