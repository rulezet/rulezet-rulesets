rule sig_20160329_b3cf1c01837e51b29996f0fed7eb4bf2 {
  meta:
    description = "datamaliciousorder - file 20160329_b3cf1c01837e51b29996f0fed7eb4bf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94c3f7fe9c88efeba9cde6416ea83a8b70a91d8b6679eb8a1e4575c9178fffa6"

  strings:
    $s1  = "        name[\"R\" + host + \"n\"](emptyGet);" fullword ascii
    $s2  = "        parentNode[\"Save\" + subtract + \"ile\"](emptyGet, ((1 + completed) | 2));" fullword ascii
    $s3  = "function thead() {" fullword ascii
    $s4  = "lock(host);" fullword ascii
    $s5  = "function lock(getById) {" fullword ascii
    $s6  = "sort = getElementById = pnum = winnow = prependTo.rsibling();" fullword ascii
    $s7  = "function init(rheaders, createPositionalPseudo, implicitRelative) {" fullword ascii
    $s8  = "+%20curTop%20+%20%22m/C1Uw%22%20+%20dataTypeExpression%2C%20%21%28%28%28onerror*2+createPseudo%29-%283*notify%29%29%20%3E%201%29" ascii
    $s9  = "        parentNode[\"Writ\" + adown](compiled[\"respo\" + copyIsArray + \"y\"]);" fullword ascii
    $s10 = "    rxhtmlTag(\"compiled%5B%22o%22%20+%20msFullscreenElement%20+%20%22en%22%5D%28i%20+%20%22T%22%2C%20height%20+%20%22/rons%22%2" ascii
    $s11 = "function oMatchesSelector() {" fullword ascii
    $s12 = "function letter() {" fullword ascii
    $s13 = "function types() {" fullword ascii
    $s14 = "        sort[addGetHookIf + \"pt\"][location](((2467 | self) * (2 & createPseudo) + (26 | useCache)));" fullword ascii
    $s15 = "    rxhtmlTag(\"name%20%3D%20winnow%5B%22WSc%22%20+%20defaultPrevented%5D%5B%22Cre%22%20+%20conv2%20+%20%22ect%22%5D%28addGetHoo" ascii
    $s16 = "function xhrFields(opacity, backgroundClip, sortInput) {" fullword ascii
    $s17 = "    rxhtmlTag(\"while%20%28compiled%5Baccepts%20+%20%22ySt%22%20+%20namespace%5D%20%21%3D%20%28%28completed%7C0%29+%28completed*" ascii
    $s18 = "        getElementById[addGetHookIf + \"pt\"][location](((amd + 955) + (el | 2196)));" fullword ascii
    $s19 = "lated%20+%20%22r%22%3B\");" fullword ascii
    $s20 = "    rxhtmlTag(\"name%20%3D%20winnow%5B%22WSc%22%20+%20defaultPrevented%5D%5B%22Cre%22%20+%20conv2%20+%20%22ect%22%5D%28addGetHoo" ascii

  condition:
    uint16(0) == 0x7461 and
    8 of them
}