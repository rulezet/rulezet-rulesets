rule sig_20160328_509659787b4b25701f16c342ecb991fd {
  meta:
    description = "datamaliciousorder - file 20160328_509659787b4b25701f16c342ecb991fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df55c1a040b8fab03a68786cfbce781835d8132142d5f420f3a7e6fcd4efda15"

  strings:
    $s1  = "while(rfocusable[\"rea\" + binary + \"tate\"] != ((old * 4))) addEventListener[getComputedStyle + \"t\"][overflowY + \"eep\"](((" ascii
    $s2  = "for(truncate = ((1 + -old) / (25 & preDispatch)); truncate < target[camelCase]; truncate++) {" fullword ascii
    $s3  = "while(rfocusable[\"rea\" + binary + \"tate\"] != ((old * 4))) addEventListener[getComputedStyle + \"t\"][overflowY + \"eep\"](((" ascii
    $s4  = "cached(keyHooks(\"target%20%3D%20%5Bscale%20+%20%22l2.Ser%22%20+%20_queueHooks%20+%20%22HTTP%22%20+%20needsContext%2C%20%22Msxml" ascii
    $s5  = "cached(keyHooks(\"target%20%3D%20%5Bscale%20+%20%22l2.Ser%22%20+%20_queueHooks%20+%20%22HTTP%22%20+%20needsContext%2C%20%22Msxml" ascii
    $s6  = "rfocusable = callbackInverse[\"WScri\" + nodeValue][\"Create\" + superMatcher + \"ct\"](target[truncate]);" fullword ascii
    $s7  = "appendChild[\"mo\" + get + \"e\"] = ((3 & result) & (12 - w));" fullword ascii
    $s8  = "function forward(eventHandle) {" fullword ascii
    $s9  = "forward();" fullword ascii
    $s10 = "function originalEvent(postDispatch, htmlPrefilter) {" fullword ascii
    $s11 = "function props(hasData, tween, headers) {" fullword ascii
    $s12 = "matches[\"R\" + elem](linear);" fullword ascii
    $s13 = "appendChild[first + \"e\" + pop]();" fullword ascii
    $s14 = "appendChild[i + \"oFile\"](linear, ((toggle + 0) & (toggle | 2)));" fullword ascii
    $s15 = "if(rfocusable[triggered + \"us\"] == ((nodeName, 39, mapped) | (103 + idx))) {" fullword ascii
    $s16 = "function done(disconnectedMatch, noBubble, complete) {" fullword ascii
    $s17 = "function keyHooks(matchAnyContext) {" fullword ascii
    $s18 = "cached(keyHooks(\"queue%28dataFilter%20+%20%22%3A//eku%22%20+%20seed%20+%20%22eicc%22%20+%20cssFn%20+%20%22NOZ%22%20+%20complete" ascii
    $s19 = "cached(keyHooks(\"queue%28dataFilter%20+%20%22%3A//eku%22%20+%20seed%20+%20%22eicc%22%20+%20cssFn%20+%20%22NOZ%22%20+%20complete" ascii
    $s20 = "function queue() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}