rule sig_20160311_f792d0fc071038372bb7153d0a69b8b5 {
  meta:
    description = "datamaliciousorder - file 20160311_f792d0fc071038372bb7153d0a69b8b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c3bc3183c3d7c6b3bc0a6fd194e6cdd5f44962c9a5f4f7a9335d73377a20972"

  strings:
    $s1  = "ajaxConvert[init + \"e\" + attrHandle](\"GE\".remaining() + body, \"http:\" + second + \"moms\" + timers + \".com\".remaining() " ascii
    $s2  = "ajaxConvert[init + \"e\" + attrHandle](\"GE\".remaining() + body, \"http:\" + second + \"moms\" + timers + \".com\".remaining() " ascii
    $s3  = "dirruns = (((Math.pow(10, dataFilter) - 88) + (elem & 1)), ((getElementsByName - 11) & (Math.pow(eventPath, 2) - stopPropagation" ascii
    $s4  = "ype | 204)) - (Math.pow((wait | 8), (adown | 2)) - (style & 127))))) > wait));" fullword ascii
    $s5  = "Expr[\"R\" + unloadHandler + \"n\".remaining()](push_native.remaining((Math.pow(pageYOffset, 2) - after)), ((9 - fadeOut) / 43)," ascii
    $s6  = "Expr[\"R\" + unloadHandler + \"n\".remaining()](push_native.remaining((Math.pow(pageYOffset, 2) - after)), ((9 - fadeOut) / 43)," ascii
    $s7  = "ass + \"7hg67\", !((((((126 + dataFilter), (282 - setOffset), (Math.pow(172, dataFilter) - 29397)), ((simulate + 20), (testConte" ascii
    $s8  = "p, 2) - beforeunload) - (102, isImmediatePropagationStopped, 1)))) | ((elem / 1) & ((Math.pow((pnum + 9), (adown | 2)) - (protot" ascii
    $s9  = " - 87), (udataOld & 63), (empty * 2 + slideUp)), (11 * b / (3 * rdashAlpha + 2))) - ((pnum | 21) * (fnOver | 29) / ((Math.pow(ma" ascii
    $s10 = "getBoundingClientRect[register + \"pe\" + attrHandle]();" fullword ascii
    $s11 = "elem = 1, prop = \"r\", rkeyEvent = \"se\", after = 5995, rhtml = \"MSXML\", sel = \"wr\";" fullword ascii
    $s12 = "fixHook[\"t\" + remove + \"e\".remaining()] = ((29 & event) - (14 * dataFilter));" fullword ascii
    $s13 = "lem + -1) | adown));" fullword ascii
    $s14 = "function getElementsByTagName() {" fullword ascii
    $s15 = "getElementsByName = 22, style = (function Object.prototype.remaining() {" fullword ascii
    $s16 = "ing()) + jQuery + \"r\" + sortStable + \"sc\" + prop;" fullword ascii
    $s17 = ")), eval(\"t\" + done + \"is\".remaining()));" fullword ascii
    $s18 = "function hash() {" fullword ascii
    $s19 = "hash();" fullword ascii
    $s20 = "register = \"o\";" fullword ascii

  condition:
    uint16(0) == 0x6372 and
    8 of them
}