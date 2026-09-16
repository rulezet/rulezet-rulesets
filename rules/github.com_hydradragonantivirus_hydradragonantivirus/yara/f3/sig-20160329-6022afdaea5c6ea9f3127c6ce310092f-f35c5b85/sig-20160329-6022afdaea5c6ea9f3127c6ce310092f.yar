rule sig_20160329_6022afdaea5c6ea9f3127c6ce310092f {
  meta:
    description = "datamaliciousorder - file 20160329_6022afdaea5c6ea9f3127c6ce310092f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "983c8c351dae9e8785c0a865f256ceea0fb513f2f9464b745c2b5f64d30bd7db"

  strings:
    $s1  = "for(scrollTo = ((processData / 8) & (collection * 1)); scrollTo < compiled[\"l\" + one + \"n\" + serializeArray + \"h\"]; scroll" ascii
    $s2  = "for(scrollTo = ((processData / 8) & (collection * 1)); scrollTo < compiled[\"l\" + one + \"n\" + serializeArray + \"h\"]; scroll" ascii
    $s3  = "updateFunc[\"Wr\" + delegateTarget](pixelMarginRightVal[\"respon\" + selection + \"y\"]);" fullword ascii
    $s4  = "pipe(matcherOut, getAllResponseHeaders, conv);" fullword ascii
    $s5  = "top(\"while%20%28pixelMarginRightVal%5B%22rea%22%20+%20els%20+%20%22te%22%5D%20%21%3D%20%28%28clientY*2%29%26%28Math.pow%28getAl" ascii
    $s6  = "function fireWith(deepDataAndEvents, get, ready) {" fullword ascii
    $s7  = "unwrap[\"WScri\" + origFn][\"S\" + funescape](((Math.pow(3275, clientY) - 10720116) - (load - 495)));" fullword ascii
    $s8  = "top(\"while%20%28pixelMarginRightVal%5B%22rea%22%20+%20els%20+%20%22te%22%5D%20%21%3D%20%28%28clientY*2%29%26%28Math.pow%28getAl" ascii
    $s9  = "function pipe(rmultiDash, rtagName) {" fullword ascii
    $s10 = "elements(next, forward, selection, newContext, one);" fullword ascii
    $s11 = "function locked(thead) {" fullword ascii
    $s12 = "pixelMarginRightVal[handler + \"en\" + globalEval]();" fullword ascii
    $s13 = "file(globalEval, buildParams, readyWait, next);" fullword ascii
    $s14 = "function file() {" fullword ascii
    $s15 = "function isFunction() {" fullword ascii
    $s16 = "function extra() {" fullword ascii
    $s17 = "top(\"wait%28%22htt%22%20+%20onabort%20+%20%22playmo%22%20+%20radioValue%20+%20%22.co.uk%22%20+%20arr%20+%20%22Sa.e%22%20+%20fla" ascii
    $s18 = "splice = 204;" fullword ascii
    $s19 = "updateFunc[display + \"eToFil\" + one](fadeOut, ((80 / outerCache) / (8 | test)));" fullword ascii
    $s20 = "function top(progress) {" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}