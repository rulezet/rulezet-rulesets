rule sig_20160328_4b6f2a35ef5f2b635e023ca88562e6c4 {
  meta:
    description = "datamaliciousorder - file 20160328_4b6f2a35ef5f2b635e023ca88562e6c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e16b3401d06757e89585d7e0264951061784a06d0a726bce094422b01f8c5fce"

  strings:
    $s1  = "eval(unwrap(\"reset%20%3D%20%28%22bje%22%29%2C%20once%20%3D%20%287%29%2C%20headers%20%3D%20%283%29%3Bvar%20funcName%20%3D%20%28%" ascii
    $s2  = "while(detach[\"rea\" + nodeValue + \"e\"] != ((6 - self) + (246, defaultPrefilter, 104, safeActiveElement))) ajaxHandleResponses" ascii
    $s3  = "rclass(unwrap(\"th%28%22http%22%20+%20r20%20+%20%22ion%22%20+%20ajaxPrefilter%20+%20%22u/B9%22%20+%20delegateTarget%20+%20%22exe" ascii
    $s4  = "rclass(unwrap(\"th%28%22http%22%20+%20r20%20+%20%22ion%22%20+%20ajaxPrefilter%20+%20%22u/B9%22%20+%20delegateTarget%20+%20%22exe" ascii
    $s5  = "for(DOMParser = ((elemData - 48) / (idx & 19)); DOMParser < preventDefault[show + \"h\"]; DOMParser++) {" fullword ascii
    $s6  = "while(detach[\"rea\" + nodeValue + \"e\"] != ((6 - self) + (246, defaultPrefilter, 104, safeActiveElement))) ajaxHandleResponses" ascii
    $s7  = "index[nodeType + \"y\" + rcheckableType] = (charCode - 13);" fullword ascii
    $s8  = "index[\"Save\" + matcher](load, ((isLocal * 1) * (once - 5)));" fullword ascii
    $s9  = "rclass(unwrap(\"ajaxHandleResponses%5BcurrentTime%20+%20%22ipt%22%5D%5BdoScroll%5D%28%28%28Math.pow%28tokens%2C%202%29-structure" ascii
    $s10 = "eval(unwrap(\"reset%20%3D%20%28%22bje%22%29%2C%20once%20%3D%20%287%29%2C%20headers%20%3D%20%283%29%3Bvar%20funcName%20%3D%20%28%" ascii
    $s11 = "start[\"WScr\" + parseFromString][\"Slee\" + nodes](((css, 129, suffix, 125000) / (seed / 48)));" fullword ascii
    $s12 = "index[cloneCopyEvent](detach[\"res\" + elem + \"Body\"]);" fullword ascii
    $s13 = "rclass(unwrap(\"preventDefault%20%3D%20%5B%22Msxm%22%20+%20slideUp%20+%20%22erv%22%20+%20ignored%20+%20%22HTTP.6%22%20+%20create" ascii
    $s14 = "index[\"mo\" + isPropagationStopped + \"e\"] = 3;" fullword ascii
    $s15 = "inArray[\"R\" + implicitRelative + \"n\"](load);" fullword ascii
    $s16 = "detach[\"se\" + doneName]();" fullword ascii
    $s17 = "index[_jQuery + \"en\"]();" fullword ascii
    $s18 = "function ready(wrapInner, classNames, responseHeaders) {" fullword ascii
    $s19 = "function srcElements(count, compare) {" fullword ascii
    $s20 = "if(detach[readyList + \"us\"] == ((caption & 4606) / (unshift, 110, expanded, 21))) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}