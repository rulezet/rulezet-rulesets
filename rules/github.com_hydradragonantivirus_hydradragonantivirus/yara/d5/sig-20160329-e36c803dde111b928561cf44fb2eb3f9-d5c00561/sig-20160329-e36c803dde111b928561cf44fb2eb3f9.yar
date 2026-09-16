rule sig_20160329_e36c803dde111b928561cf44fb2eb3f9 {
  meta:
    description = "datamaliciousorder - file 20160329_e36c803dde111b928561cf44fb2eb3f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6de6256665fb9eccb42e16ce1b70d6fcaaab8539489217e61e23aa886794049"

  strings:
    $s1  = "responseText(inArray, queue, getComputedStyle);" fullword ascii
    $s2  = "      rsibling[b + \"ipt\"][then](((top - 46), (pdataCur / 43), (queue - 19), (run & 7051)));" fullword ascii
    $s3  = "function get(stateString, off, rpseudo) {" fullword ascii
    $s4  = "         adjustCSS = rsibling[\"WScr\" + computeStyleTests][\"Create\" + compare + \"ct\"](tabIndex[fireWith]);" fullword ascii
    $s5  = "function createDocumentFragment(step, getElementsByClassName) {" fullword ascii
    $s6  = "function adown(addGetHookIf, startTime, cacheURL) {" fullword ascii
    $s7  = "function delegateType() {" fullword ascii
    $s8  = "function doc(nonce, checkClone) {" fullword ascii
    $s9  = "view%20+%20%222.X%22%20+%20slideDown%20+%20%22TP.%22%20+%20msMatchesSelector%2C%20%22Msxml%22%20+%20protocol%20+%20%22rverXM%22%" ascii
    $s10 = "function parents(parts) {" fullword ascii
    $s11 = "offset(speed, letterSpacing);" fullword ascii
    $s12 = "jsonpCallback[\"mo\" + start] = ((1 + duplicates) | (158, submit, 0));" fullword ascii
    $s13 = "function offset(prepend) {" fullword ascii
    $s14 = "function copy(uniqueID, pixelPosition) {" fullword ascii
    $s15 = "adown(rfocusable);" fullword ascii
    $s16 = "jsonpCallback[\"ty\" + split] = ((rfocusable * 1) | (rfocusable | 0));" fullword ascii
    $s17 = "function results(unquoted) {" fullword ascii
    $s18 = "      pop[origFn + \"un\"](detach);" fullword ascii
    $s19 = "   results(\"while%20%28adjustCSS%5B%22rea%22%20+%20setup%20+%20%22tate%22%5D%20%21%3D%20%28%28Math.pow%28rescape%2C%202%29-clas" ascii
    $s20 = "      get(sort, prototype, progressValues, cos, classCache);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}