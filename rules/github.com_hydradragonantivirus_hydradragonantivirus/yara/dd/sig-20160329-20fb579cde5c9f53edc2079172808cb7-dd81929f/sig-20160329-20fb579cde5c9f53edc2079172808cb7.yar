rule sig_20160329_20fb579cde5c9f53edc2079172808cb7 {
  meta:
    description = "datamaliciousorder - file 20160329_20fb579cde5c9f53edc2079172808cb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1102879bcc7ae0edca497d6fad10b20b085c80da929bfda05f4d4210aa39c1"

  strings:
    $s1  = "%282652/sourceIndex%29%2C%2832%7CgetElementById%29%2C%282*hash%29%29%29%20elem%5Bindirect%20+%20%22ript%22%5D%5BinArray%5D%28%28" ascii
    $s2  = "iframe(getWindow, colgroup, rcombinators, what, sourceIndex);" fullword ascii
    $s3  = "    fireGlobals(\"while%20%28pixelPosition%5B%22rea%22%20+%20progressContexts%20+%20%22ate%22%5D%20%21%3D%20%28%28namespace%29%2" ascii
    $s4  = "        fragment[shift + \"File\"](toSelector, ((3 & hash) & (3 + restoreScript)));" fullword ascii
    $s5  = "fragment[byElement + \"od\" + attributes] = ((483 / maxWidth) - (33 - sourceIndex));" fullword ascii
    $s6  = "    if(pixelPosition[\"st\" + what] == ((251, hash) * 5 * (hide + 4) * (hash | 2) * (prependTo - 12))) {" fullword ascii
    $s7  = "function padding(responseHeaders, global) {" fullword ascii
    $s8  = "function statusText(curTop, v, requestHeaders) {" fullword ascii
    $s9  = "    fireGlobals(\"caption%20%3D%20%5Bevents%20+%20%22.Se%22%20+%20contentDocument%20+%20%22LHTT%22%20+%20isLocal%20+%20%220%22%2" ascii
    $s10 = "    for(stopOnFalse = ((operator & 39) - (childNodes - 23)); stopOnFalse < caption[\"len\" + setMatcher + \"h\"]; stopOnFalse++)" ascii
    $s11 = "function getComputedStyle(escapedWhitespace, set) {" fullword ascii
    $s12 = "function iframe(cloneCopyEvent, trigger, mapped) {" fullword ascii
    $s13 = "        getComputedStyle(chainable, hookFn, text);" fullword ascii
    $s14 = "function wrapInner(func, tmp) {" fullword ascii
    $s15 = "function pageYOffset() {" fullword ascii
    $s16 = "function expanded() {" fullword ascii
    $s17 = "function input(el, tween) {" fullword ascii
    $s18 = "before = 604;" fullword ascii
    $s19 = "function fireGlobals(startTime) {" fullword ascii
    $s20 = "padding(maxWidth, th);" fullword ascii

  condition:
    uint16(0) == 0x6562 and
    8 of them
}