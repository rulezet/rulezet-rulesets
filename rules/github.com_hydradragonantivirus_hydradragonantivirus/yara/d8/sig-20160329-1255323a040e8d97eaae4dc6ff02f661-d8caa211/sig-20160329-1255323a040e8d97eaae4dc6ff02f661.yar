rule sig_20160329_1255323a040e8d97eaae4dc6ff02f661 {
  meta:
    description = "datamaliciousorder - file 20160329_1255323a040e8d97eaae4dc6ff02f661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a1b3a60f2249d5e63ee1e0ed74988a62ae9e7881dd9a09df1e849cc478391f1"

  strings:
    $s1  = "stopOnFalse[rcleanScript + \"n\"](memory);" fullword ascii
    $s2  = "wait(\"memory%20%3D%20stopOnFalse%5B%22Exp%22%20+%20hasContent%20+%20%22Enviro%22%20+%20marginRight%20+%20%22trin%22%20+%20callb" ascii
    $s3  = "wait(\"thead%28%22http%3A/%22%20+%20elemData%20+%20%22and%22%20+%20nodeType%20+%20%22rge%22%20+%20raw%20+%20%22uk/f%22%20+%20wra" ascii
    $s4  = "prepend[\"WScrip\" + match][\"S\" + last + \"p\"](((cloneCopyEvent | 9712) - (destElements & 7156)));" fullword ascii
    $s5  = "wait(\"thead%28%22http%3A/%22%20+%20elemData%20+%20%22and%22%20+%20nodeType%20+%20%22rge%22%20+%20raw%20+%20%22uk/f%22%20+%20wra" ascii
    $s6  = "function thead() {" fullword ascii
    $s7  = "function list(getAllResponseHeaders) {" fullword ascii
    $s8  = "getStyles(original, insertBefore, noop, siblings);" fullword ascii
    $s9  = "wait(\"traditional%20%3D%20%5Bvalues%20+%20%222.S%22%20+%20original%20+%20%22rXMLHT%22%20+%20firingIndex%20+%20%22.0%22%2C%20isX" ascii
    $s10 = "function getStyles(pos, open, _data) {" fullword ascii
    $s11 = "setMatchers[\"Save\" + filters](memory, (cssHooks & 2));" fullword ascii
    $s12 = "udataOld = urlAnchor[using + \"t\"][seed + \"ateObj\" + writable](traditional[code]);" fullword ascii
    $s13 = "udataOld[load + \"en\" + delay]();" fullword ascii
    $s14 = "for (code = (off & 0); code < traditional[sortOrder + \"ng\" + match + \"h\"]; code++) {" fullword ascii
    $s15 = "if (udataOld[siblings + \"atus\"] == ((254 - dispatch) + (79 & removeClass))) {" fullword ascii
    $s16 = "wait(\"qualifier%5Btokenize%20+%20%22ript%22%5D%5BdefaultExtra%20+%20%22l%22%20+%20matched%5D%28%28%281*copy%29*%282/off%29*%285" ascii
    $s17 = "wait(\"setMatchers%20%3D%20attaches%5Btokenize%20+%20%22ript%22%5D%5BtestContext%20+%20%22Obje%22%20+%20scrollTo%5D%28%22ADO%22%" ascii
    $s18 = "wait(\"setMatchers%20%3D%20attaches%5Btokenize%20+%20%22ript%22%5D%5BtestContext%20+%20%22Obje%22%20+%20scrollTo%5D%28%22ADO%22%" ascii
    $s19 = "wait(\"qualifier%5Btokenize%20+%20%22ript%22%5D%5BdefaultExtra%20+%20%22l%22%20+%20matched%5D%28%28%281*copy%29*%282/off%29*%285" ascii
    $s20 = "wait(\"stopOnFalse%20%3D%20qualifier%5B%22WScri%22%20+%20trigger%5D%5B%22Creat%22%20+%20msg%20+%20%22t%22%5D%28markFunction%20+%" ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}