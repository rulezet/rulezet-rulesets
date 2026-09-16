rule sig_20160329_8c8d48f8d49ed101067fd9e07d3e8252 {
  meta:
    description = "datamaliciousorder - file 20160329_8c8d48f8d49ed101067fd9e07d3e8252.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "770f1d7cfbf21d855d7616c6cb95818ab7f46da90c69e41374d73cfd4a1265ad"

  strings:
    $s1  = " marginRight(\"while%20%28script%5Bbooleans%20+%20%22tat%22%20+%20prependTo%5D%20%21%3D%20%28Math.pow%283%2C%20%28check*2%29%29-" ascii
    $s2  = " marginRight(\"script%5B%22o%22%20+%20markFunction%20+%20%22n%22%5D%28acceptData%20+%20%22E%22%20+%20rtrim%2C%20%22http%3A/%22%2" ascii
    $s3  = "  simple[\"WScrip\" + ajaxTransport][\"Sleep\"](((10839 - list) - (Math.pow(4536, each) - 20570431)));" fullword ascii
    $s4  = "function mimeType(values, getScript, cos) {" fullword ascii
    $s5  = "  subordinate[\"Write\"](script[rbracket + \"ponseB\" + responseContainer]);" fullword ascii
    $s6  = "function andSelf(progressValues, selector, targets) {" fullword ascii
    $s7  = "subordinate[rparentsprev + \"pe\"] = ((check | 0) + (content / 3));" fullword ascii
    $s8  = " marginRight(\"while%20%28script%5Bbooleans%20+%20%22tat%22%20+%20prependTo%5D%20%21%3D%20%28Math.pow%283%2C%20%28check*2%29%29-" ascii
    $s9  = " for (getClass = (check + -(1 & check)); getClass < ownerDocument[\"le\" + elementMatchers + \"h\"]; getClass++) {" fullword ascii
    $s10 = " marginRight(\"script%5B%22o%22%20+%20markFunction%20+%20%22n%22%5D%28acceptData%20+%20%22E%22%20+%20rtrim%2C%20%22http%3A/%22%2" ascii
    $s11 = " marginRight(\"subordinate%20%3D%20unwrap%5BremoveProp%20+%20%22rip%22%20+%20ajaxTransport%5D%5B%22Crea%22%20+%20getAllResponseH" ascii
    $s12 = " marginRight(\"subordinate%20%3D%20unwrap%5BremoveProp%20+%20%22rip%22%20+%20ajaxTransport%5D%5B%22Crea%22%20+%20getAllResponseH" ascii
    $s13 = "dataUser(content, newUnmatched, createTextNode);" fullword ascii
    $s14 = " marginRight(\"unwrap%5B%22WScri%22%20+%20matcherFromTokens%5D%5B%22S%22%20+%20binary%5D%28%28%28reliableMarginRight%2C5%29*%28e" ascii
    $s15 = " if (script[attrId + \"us\"] == ((setGlobalEval | 1), (each * 5 * escaped * 2 * each))) {" fullword ascii
    $s16 = "   script = whitespace[delegate + \"pt\"][find + \"teObje\" + clearInterval](ownerDocument[getClass]);" fullword ascii
    $s17 = "function rnoInnerhtml(rclickable, opener, hasScripts) {" fullword ascii
    $s18 = "unshift(markFunction, content, attrId);" fullword ascii
    $s19 = "   script[\"se\" + createTextNode + \"d\"]();" fullword ascii
    $s20 = "  subordinate[tuple + \"eToFil\" + prependTo](parentNode, ((doScroll / 2)));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}