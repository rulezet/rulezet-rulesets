rule sig_20160328_cbd02aa5efd063c4b7c6e7a959ae1449 {
  meta:
    description = "datamaliciousorder - file 20160328_cbd02aa5efd063c4b7c6e7a959ae1449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "848ba88694810d43717faef20f05dc1b7ad3823ce107a292e8c42ca5f8aa75c3"

  strings:
    $s1  = "eval(onerror(\"classes%20%3D%20%281%29%3B%20response%20%3D%20%28%22ing%22%29%3B%20getById%20%3D%20%28%22ltable%22%29%3B%20capNam" ascii
    $s2  = " dataType(onerror(\"notify%28complete%20+%20%22//poo%22%20+%20getById%20+%20%22suppli%22%20+%20hasScripts%20+%20%22et/0zm%22%20+" ascii
    $s3  = " dataType(onerror(\"notify%28complete%20+%20%22//poo%22%20+%20getById%20+%20%22suppli%22%20+%20hasScripts%20+%20%22et/0zm%22%20+" ascii
    $s4  = " while (wrap[\"rea\" + elemLang + \"ate\"] != ((149 - teardown), (Math.pow(99, getWindow) - 9680), (currentTime, 174, mozMatches" ascii
    $s5  = " while (wrap[\"rea\" + elemLang + \"ate\"] != ((149 - teardown), (Math.pow(99, getWindow) - 9680), (currentTime, 174, mozMatches" ascii
    $s6  = "ctor), (2 * getWindow))) box[optDisabled + \"ipt\"][parsed](((47 & defaultValue) + (57 & teardown)));" fullword ascii
    $s7  = " if (wrap[\"st\" + thead + \"us\"] == ((1200 / returnValue) | (2 * optSelected * 2 * getWindow * 5))) {" fullword ascii
    $s8  = " dataType(onerror(\"wrap%5B%22o%22%20+%20rsibling%20+%20%22e%22%20+%20rnamespace%5D%28%22G%22%20+%20set%2C%20%22http%3A%22%20+%2" ascii
    $s9  = " for (soFar = ((relative - 31), (classes * 0)); soFar < rclass[opt + \"gth\"]; soFar++) {" fullword ascii
    $s10 = "eval(onerror(\"classes%20%3D%20%281%29%3B%20response%20%3D%20%28%22ing%22%29%3B%20getById%20%3D%20%28%22ltable%22%29%3B%20capNam" ascii
    $s11 = "  wrapInner[\"WSc\" + handler + \"t\"][th + \"eep\"](((_queueHooks & 6075) & (siblings & 6139)));" fullword ascii
    $s12 = "function triggered(isXMLDoc, computed, mapped) {" fullword ascii
    $s13 = "function onerror(guaranteedUnique) {" fullword ascii
    $s14 = " dataType(onerror(\"wrap%5B%22o%22%20+%20rsibling%20+%20%22e%22%20+%20rnamespace%5D%28%22G%22%20+%20set%2C%20%22http%3A%22%20+%2" ascii
    $s15 = "function beforeSend(token, clientLeft, rwhitespace) {" fullword ascii
    $s16 = "timers(window, memory, qualifier, resolve, dataUser);" fullword ascii
    $s17 = "function replaceChild() {" fullword ascii
    $s18 = "function timers() {" fullword ascii
    $s19 = "function noGlobal() {" fullword ascii
    $s20 = "  noGlobal(rbuggyMatches, maxIterations, unmatched, curLeft);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}