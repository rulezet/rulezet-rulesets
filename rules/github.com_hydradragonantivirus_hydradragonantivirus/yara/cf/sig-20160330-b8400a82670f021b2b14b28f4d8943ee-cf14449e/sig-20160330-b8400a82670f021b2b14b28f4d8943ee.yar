rule sig_20160330_b8400a82670f021b2b14b28f4d8943ee {
  meta:
    description = "datamaliciousorder - file 20160330_b8400a82670f021b2b14b28f4d8943ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ea7727586ae1eae493211e76efd9f172221ce10b71c4a033da49186a0bcaa0d"

  strings:
    $s1  = "for(letterSpacing = ((1 + iterator) + -(1 & which)); letterSpacing < wrapInner[\"length\"]; letterSpacing++) {" fullword ascii
    $s2  = "unit(input, getAttributeNode, trigger, empty, qsa);" fullword ascii
    $s3  = "function getElementsByTagName(boolHook, propName) {" fullword ascii
    $s4  = "function suffix(host, teardown, pixelPosition) {" fullword ascii
    $s5  = "suffix(postFilter, inspect, string, firstChild, initial);" fullword ascii
    $s6  = "cloneNode(serialize, pdataOld, padding, requestHeaders);" fullword ascii
    $s7  = "ap(\"while&20&28types&5BgetAttributeNode&20+&20&22dyS&22&20+&20dataFilter&5D&20&21&3D&20&28&283+funcName&29&26&285+which&29&29&2" ascii
    $s8  = "if(types[\"st\" + inspect] == ((25 / padding) * (2 + iterator) * (2 | iterator) * (5 | which) * (1 * funcName))) {" fullword ascii
    $s9  = "ap(\"while&20&28types&5BgetAttributeNode&20+&20&22dyS&22&20+&20dataFilter&5D&20&21&3D&20&28&283+funcName&29&26&285+which&29&29&2" ascii
    $s10 = "stored[expand + \"n\"](originalProperties);" fullword ascii
    $s11 = "root(handler);" fullword ascii
    $s12 = "function timeStamp() {" fullword ascii
    $s13 = "function cssText() {" fullword ascii
    $s14 = "function unit() {" fullword ascii
    $s15 = "function ap(crossDomain) {" fullword ascii
    $s16 = "index(funcName, offset, rnamespace, nativeStatusText, documentElement);" fullword ascii
    $s17 = "Inner&5BletterSpacing&5D&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s18 = "function evt(overwritten, _removeData) {" fullword ascii
    $s19 = "test = 356;" fullword ascii
    $s20 = "Symbol(cur, using, th);" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    8 of them
}