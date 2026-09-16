rule sig_20160329_beaf147d9bcec63706f777ee706dcbb5 {
  meta:
    description = "datamaliciousorder - file 20160329_beaf147d9bcec63706f777ee706dcbb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05d7876f218fc83678a1cd97eddcb8a33c42724625e467f30763dd995bc7938a"

  strings:
    $s1  = "doAnimation[pixelPosition + \"ipt\"][MAX_NEGATIVE + \"leep\"]((Math.pow((Math.pow(rmargin, 2) - setter), (36 - response)) - (196" ascii
    $s2  = "locked[\"ty\" + rbuggyQSA] = ((27 & maxIterations) - (Math.pow(24, unit) - 550));" fullword ascii
    $s3  = "rdashAlpha(\"while%20%28inspected%5B%22rea%22%20+%20cleanData%20+%20%22ate%22%5D%20%21%3D%20%28%2822-addCombinator%29+0%29%29%20" ascii
    $s4  = "doAnimation[pixelPosition + \"ipt\"][MAX_NEGATIVE + \"leep\"]((Math.pow((Math.pow(rmargin, 2) - setter), (36 - response)) - (196" ascii
    $s5  = "locked[easing + \"ite\"](inspected[postDispatch + \"seBody\"]);" fullword ascii
    $s6  = "locked[operator + \"eToFil\" + compilerCache](until, 2);" fullword ascii
    $s7  = "cssFn(MAX_NEGATIVE, addEventListener, cur, getter);" fullword ascii
    $s8  = "for(arr = (size + -1); arr < count[\"length\"]; arr++) {" fullword ascii
    $s9  = "locked[inPage + \"o\" + visibility] = ((4 - size) & (38 - parseFromString));" fullword ascii
    $s10 = "script(rclass, before, getter, doc);" fullword ascii
    $s11 = "rdashAlpha(\"delegate%20%3D%20doAnimation%5B%22WSc%22%20+%20rrun%5D%5B%22Crea%22%20+%20cur%20+%20%22ect%22%5D%28hasCompare%20+%2" ascii
    $s12 = "function script(position, removeAttr) {" fullword ascii
    $s13 = "rdashAlpha(\"delegate%20%3D%20doAnimation%5B%22WSc%22%20+%20rrun%5D%5B%22Crea%22%20+%20cur%20+%20%22ect%22%5D%28hasCompare%20+%2" ascii
    $s14 = "locked[matched + \"en\"]();" fullword ascii
    $s15 = "inspected = pos[doneName + \"pt\"][maxWidth + \"Objec\" + slow](count[arr]);" fullword ascii
    $s16 = "inspected[isSuccess + \"en\" + Symbol]();" fullword ascii
    $s17 = "delegate[\"R\" + nextAll](until);" fullword ascii
    $s18 = "function replaceWith(fxNow, condense, completed) {" fullword ascii
    $s19 = "rnamespace(hasCompare, isSuccess, lock, leadingRelative, maxWidth);" fullword ascii
    $s20 = "rdashAlpha(\"until%20%3D%20delegate%5Btokens%20+%20%22dEn%22%20+%20nodeName%20+%20%22nment%22%20+%20originalProperties%20+%20%22" ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}