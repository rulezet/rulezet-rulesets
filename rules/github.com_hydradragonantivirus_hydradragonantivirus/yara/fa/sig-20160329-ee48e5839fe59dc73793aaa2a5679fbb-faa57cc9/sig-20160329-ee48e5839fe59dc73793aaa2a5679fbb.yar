rule sig_20160329_ee48e5839fe59dc73793aaa2a5679fbb {
  meta:
    description = "datamaliciousorder - file 20160329_ee48e5839fe59dc73793aaa2a5679fbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bade5b8dd6a478138c6016e66dfd374e80d033b1b3b21c0a7581f0accb22fe6f"

  strings:
    $s1  = "a(\"access%28%22http%3A%22%20+%20targets%20+%20%22ad.com%22%20+%20refElements%20+%20%22Uwh%22%20+%20initialInUnit%20+%20%22xe%22" ascii
    $s2  = "a(\"access%28%22http%3A%22%20+%20targets%20+%20%22ad.com%22%20+%20refElements%20+%20%22Uwh%22%20+%20initialInUnit%20+%20%22xe%22" ascii
    $s3  = "operator[\"WScri\" + settings][\"S\" + relative + \"p\"](((Math.pow(seekingTransport, 2) - cloneNode) & (6923 | notify)));" fullword ascii
    $s4  = "function a(currentTarget) {" fullword ascii
    $s5  = "html = deep[\"WSc\" + htmlPrefilter + \"t\"][currentTime + \"Object\"](uid[hasCompare]);" fullword ascii
    $s6  = "return url(unescape(currentTarget));" fullword ascii
    $s7  = "letter = deep = operator = simple = checked.curCSSTop();" fullword ascii
    $s8  = "createElement(timer, postFinder, notifyWith, unique, urlAnchor);" fullword ascii
    $s9  = "if (html[stopped + \"us\"] == ((on / 9) & (_ * 2 + src))) {" fullword ascii
    $s10 = "function timerId(getElementsByClassName, tmp) {" fullword ascii
    $s11 = "function qsaError(defaultExtra, fadeToggle) {" fullword ascii
    $s12 = "a(\"simple%5B%22WSc%22%20+%20collection%5D%5B%22S%22%20+%20attrHandle%5D%28%28%28Math.pow%281027%2C%20origFn%29-1053607%29*%28cs" ascii
    $s13 = "qsaError(unique, htmlPrefilter);" fullword ascii
    $s14 = "guid(isXMLDoc, inspectPrefiltersOrTransports, createButtonPseudo, notify, noBubble);" fullword ascii
    $s15 = "timeStamp(pushStack, seekingTransport, ajax, support);" fullword ascii
    $s16 = "a(\"simple%5B%22WSc%22%20+%20collection%5D%5B%22S%22%20+%20attrHandle%5D%28%28%28Math.pow%281027%2C%20origFn%29-1053607%29*%28cs" ascii
    $s17 = "a(\"while%20%28html%5Bsel%20+%20%22tat%22%20+%20ajax%5D%20%21%3D%20%28%28timers*25%29-%28fns/22%29%29%29%20letter%5B%22WScrip%22" ascii
    $s18 = "String%20+%20%22t.She%22%20+%20write%29%3B\");" fullword ascii
    $s19 = "function ajaxSetup() {" fullword ascii
    $s20 = "function toArray(animate, vendorPropName) {" fullword ascii

  condition:
    uint16(0) == 0x7266 and
    8 of them
}