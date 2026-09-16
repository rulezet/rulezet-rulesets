rule sig_20160328_ff0695e6bc9ea2f397b0e1a33d441f60 {
  meta:
    description = "datamaliciousorder - file 20160328_ff0695e6bc9ea2f397b0e1a33d441f60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd840c457e9509b40ceedde2db35b88b39cd2144853f625449eb7a9698fc4d1"

  strings:
    $s1  = "childNodes(getElementById(\"dispatch%20%3D%20cur%5B%22Expand%22%20+%20xhrSupported%20+%20%22onm%22%20+%20num%20+%20%22ing%22%20+" ascii
    $s2  = "while (returnValue[addEventListener + \"ySt\" + curValue] != ((completeDeferred - 7) | (newContext * 4))) toggle[\"WScr\" + chec" ascii
    $s3  = "while (returnValue[addEventListener + \"ySt\" + curValue] != ((completeDeferred - 7) | (newContext * 4))) toggle[\"WScr\" + chec" ascii
    $s4  = "text][\"Sle\" + uniqueSort + \"p\"](((Math.pow(destElements, 2) - parseJSON) / (1840 / defaultValue)));" fullword ascii
    $s5  = "childNodes(getElementById(\"fn%5Bprop%20+%20%22t%22%5D%5BtabIndex%20+%20%22leep%22%5D%28%28%282*last*2*last*37*last%29+%283688%7" ascii
    $s6  = "childNodes(getElementById(\"fn%5Bprop%20+%20%22t%22%5D%5BtabIndex%20+%20%22leep%22%5D%28%28%282*last*2*last*37*last%29+%283688%7" ascii
    $s7  = "childNodes(getElementById(\"dispatch%20%3D%20cur%5B%22Expand%22%20+%20xhrSupported%20+%20%22onm%22%20+%20num%20+%20%22ing%22%20+" ascii
    $s8  = "if (returnValue[leadingRelative + \"tus\"] == ((Math.pow(104, last) - 10612) & (mapped * 5 + classCache))) {" fullword ascii
    $s9  = "Attribute%20%3D%20%28%22.et%22%29%2C%20curPosition%20%3D%20%28%22totype%22%29%2C%20apply%20%3D%20%28%22Msx%22%29%3Bgetter%20%3D%" ascii
    $s10 = "seed(getter, size, getter, parseJSON, count);" fullword ascii
    $s11 = "throws(getter, curPosition);" fullword ascii
    $s12 = "function getElementById(suffix) {" fullword ascii
    $s13 = "fn[file + \"ipt\"][conv2 + \"p\"](((53023 + allTypes) / (34 | selected)));" fullword ascii
    $s14 = "cur[wrapMap + \"n\"](dispatch);" fullword ascii
    $s15 = "function set(stopped, addCombinator) {" fullword ascii
    $s16 = "function currentValue(hookFn, unit, ajaxTransport) {" fullword ascii
    $s17 = "function nodes() {" fullword ascii
    $s18 = "function fireWith() {" fullword ascii
    $s19 = "function throws(pageYOffset, realStringObj) {" fullword ascii
    $s20 = "send(match, index, delay, wrapMap);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}