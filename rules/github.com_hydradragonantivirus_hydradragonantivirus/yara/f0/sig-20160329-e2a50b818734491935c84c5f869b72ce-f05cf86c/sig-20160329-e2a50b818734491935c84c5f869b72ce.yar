rule sig_20160329_e2a50b818734491935c84c5f869b72ce {
  meta:
    description = "datamaliciousorder - file 20160329_e2a50b818734491935c84c5f869b72ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "317fc0abc59a3fa29f7680607ca4c14666469330a7afbe8764954bf4f3a861c4"

  strings:
    $s1  = "access[\"m\" + host + \"e\"] = ((3 & resolve) & 3);" fullword ascii
    $s2  = "        start(elementMatcher, match, getStyles, host, ready);" fullword ascii
    $s3  = "thead(ready, linear, reject, adown);" fullword ascii
    $s4  = "function remove(emptyGet, clearCloneStyle, addToPrefiltersOrTransports) {" fullword ascii
    $s5  = "    dest(\"shift%20%3D%20%5B%22Msxml2%22%20+%20readyWait%20+%20%22ver%22%20+%20support%20+%20%22TTP%22%20+%20first%2C%20%22Msx%2" ascii
    $s6  = "function thead() {" fullword ascii
    $s7  = "        high[\"WSc\" + compilerCache][\"Sleep\"]((Math.pow((PI | 3656), (filter)) - (Math.pow(8427906, filter) - 71029585933736)" ascii
    $s8  = "function dest(tokens) {" fullword ascii
    $s9  = "propHooks(match, configurable);" fullword ascii
    $s10 = "    dest(\"shift%20%3D%20%5B%22Msxml2%22%20+%20readyWait%20+%20%22ver%22%20+%20support%20+%20%22TTP%22%20+%20first%2C%20%22Msx%2" ascii
    $s11 = "function responses() {" fullword ascii
    $s12 = "result();" fullword ascii
    $s13 = "function prevAll() {" fullword ascii
    $s14 = "function result(insertBefore) {" fullword ascii
    $s15 = "access[ontype + \"p\" + oldCallbacks] = (andSelf & 1);" fullword ascii
    $s16 = "chainable = write = image = high = one.attrs();" fullword ascii
    $s17 = "argument = 182;" fullword ascii
    $s18 = "function propHooks(unmatched, fireWith) {" fullword ascii
    $s19 = "function clientLeft(els, origName, src) {" fullword ascii
    $s20 = "elems(iNoClone, isEmptyObject, unloadHandler, each, progressContexts);" fullword ascii

  condition:
    uint16(0) == 0x7261 and
    8 of them
}