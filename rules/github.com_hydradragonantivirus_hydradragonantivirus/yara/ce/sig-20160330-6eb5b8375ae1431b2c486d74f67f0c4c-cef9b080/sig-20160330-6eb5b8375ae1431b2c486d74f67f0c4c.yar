rule sig_20160330_6eb5b8375ae1431b2c486d74f67f0c4c {
  meta:
    description = "datamaliciousorder - file 20160330_6eb5b8375ae1431b2c486d74f67f0c4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd455e66e9f5e2aae0944bce2ed9866437e9a837a46e9bc76166224df1f5b0ca"

  strings:
    $s1  = "eval(unescape([\"curPosition&20&3D&20&28&22http&3A&22&29&2C&20dataFilter&20&3D&20&28&22p&22&29&2C&20promise&20&3D&20&\", \"28&22" ascii
    $s2  = "reliableMarginRight[\"s\" + temp + \"n\" + display]();" fullword ascii
    $s3  = ") - 6098), (Math.pow(parseFromString, 2) - returned)));" fullword ascii
    $s4  = "cssShow[detach + \"pt\"][prefilterOrFactory + \"eep\"](((Math.pow(setter, 2) - pageY), (242, css, 16, _jQuery), (Math.pow(79, in" ascii
    $s5  = "errorCallback[unbind + \"o\" + getComputedStyle] = ((123, msg, 3));" fullword ascii
    $s6  = "cssShow[detach + \"pt\"][prefilterOrFactory + \"eep\"](((Math.pow(setter, 2) - pageY), (242, css, 16, _jQuery), (Math.pow(79, in" ascii
    $s7  = "function rscriptTypeMasked(setMatchers, compareDocumentPosition) {" fullword ascii
    $s8  = "if(reliableMarginRight[\"stat\" + round] == ((setup - 165) & (finalValue & 239))) {" fullword ascii
    $s9  = "soFar&20&3D&20&28&22Sleep&22&29&2C&20optSelected&20&\", \"3D&20eval&2C&20isTrigger&20&3D&20&28&22WSc&22&29&3Bvar&20getJSON&20&3D" ascii
    $s10 = "eventHandle(\"while&20&28reliableMarginRight&5B&22ready&22&20+&20promise&20+&20&22e&22&5D&20&21&3D&20&28&281*funescape&29*&281+s" ascii
    $s11 = "for(matchExpr = ((funescape) + -(198, high, 29, funescape)); matchExpr < noGlobal[\"leng\" + etag]; matchExpr++) {" fullword ascii
    $s12 = "ache&20&3D&20&28&22protot&22&29&3Bround&20&3D&20&28&22us&22&\", \"29&3B&20readyList&20&3D&20&28&22eOb&22&29&3B&20propHooks&20&3D" ascii
    $s13 = "errorCallback[original + \"te\"](reliableMarginRight[attrs + \"seBody\"]);" fullword ascii
    $s14 = "oldfire(unbind, isReady, parts, original, funescape);" fullword ascii
    $s15 = "function Callbacks(postMap) {" fullword ascii
    $s16 = "function buildFragment() {" fullword ascii
    $s17 = "function col() {" fullword ascii
    $s18 = "function map(rsingleTag, options, fns) {" fullword ascii
    $s19 = "function mouseenter(progressValues, tweener) {" fullword ascii
    $s20 = "function oldfire(start) {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}