rule sig_20160328_6c89882a049f96e4b654935e29ec865d {
  meta:
    description = "datamaliciousorder - file 20160328_6c89882a049f96e4b654935e29ec865d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "435250d7e2bb09fac2b8b91af9590baac92289cc80d9f11db5e06a16cf4c1d4e"

  strings:
    $s1  = "  pos(pushStack(\"button%20%3D%20%5B%22Msxml2%22%20+%20append%20+%20%22erX%22%20+%20fadeOut%20+%20%22TP.6%22%20+%20always%2C%20%" ascii
    $s2  = "  while (_queueHooks[\"rea\" + cssText + \"e\"] != ((295 - marginRight), (20, setOffset, 227, lock), 4)) unmatched[unshift + \"r" ascii
    $s3  = "[swap](((xml * 2 * progressValues * 2) * (isImmediatePropagationStopped | 4) + (Math.pow(progressValues, 2) - isLocal)));" fullword ascii
    $s4  = "responseType(display, stopImmediatePropagation, swap, ajaxSettings, relatedTarget);" fullword ascii
    $s5  = "  while (_queueHooks[\"rea\" + cssText + \"e\"] != ((295 - marginRight), (20, setOffset, 227, lock), 4)) unmatched[unshift + \"r" ascii
    $s6  = "unmatched = selection = transport = curTop = reliableMarginLeft.fns();" fullword ascii
    $s7  = "  pos(pushStack(\"selection%5B%22WSc%22%20+%20show%5D%5B%22Sl%22%20+%20pageY%5D%28%28%28155*ajaxSettings+40%29%26%28hasScripts+1" ascii
    $s8  = "  pos(pushStack(\"selection%5B%22WSc%22%20+%20show%5D%5B%22Sl%22%20+%20pageY%5D%28%28%28155*ajaxSettings+40%29%26%28hasScripts+1" ascii
    $s9  = "    transport[\"WScr\" + buildParams][\"Sleep\"](((3321 + pageX) - (5485 & onabort)));" fullword ascii
    $s10 = "function addGetHookIf(func) {" fullword ascii
    $s11 = "  for (cloneCopyEvent = ((height / 13) * handleObjIn); cloneCopyEvent < button[\"len\" + srcElements]; cloneCopyEvent++) {" fullword ascii
    $s12 = "function%20reliableMarginLeft.fns%28%29%7Bvar%20fx%3D%20%5B%5D%5B%22con%22%20+%20ajaxConvert%20+%20%22or%22%5D%5Bnow%20+%20%22yp" ascii
    $s13 = "function rhash(rwhitespace, newSelector) {" fullword ascii
    $s14 = "function responseFields() {" fullword ascii
    $s15 = "function tween() {" fullword ascii
    $s16 = "function Expr() {" fullword ascii
    $s17 = "function pushStack(selectors) {" fullword ascii
    $s18 = "ajaxExtend(clearQueue, status);" fullword ascii
    $s19 = "  pos(pushStack(\"button%20%3D%20%5B%22Msxml2%22%20+%20append%20+%20%22erX%22%20+%20fadeOut%20+%20%22TP.6%22%20+%20always%2C%20%" ascii
    $s20 = "function responseType(slideUp, resolveContexts) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}