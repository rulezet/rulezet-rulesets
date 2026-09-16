rule sig_20160329_bd45e074c14cd61a70d8fd89254c557a {
  meta:
    description = "datamaliciousorder - file 20160329_bd45e074c14cd61a70d8fd89254c557a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "570f78787530b5162e33efdf2dc9ad337303a01ca84dfa765503092f5eeb1dbd"

  strings:
    $s1  = "function getAttributeNode(keepScripts, _load, matcherFromTokens) {" fullword ascii
    $s2  = "diff(\"simple%20%3D%20selectedIndex%5B%22Exp%22%20+%20optionSet%20+%20%22viron%22%20+%20expando%20+%20%22trings%22%5D%28optSelec" ascii
    $s3  = "ajaxHandleResponses[password + \"nd\"]();" fullword ascii
    $s4  = "rsubmitterTypes[\"Sav\" + rdashAlpha + \"Fil\" + stopImmediatePropagation](simple, ((87 - exports) / 43));" fullword ascii
    $s5  = "rsubmitterTypes[\"mo\" + getWidthOrHeight] = ((45 / protocol));" fullword ascii
    $s6  = "Order%20+%20%223.0%22%2CpostFilter%20+%20%22.XML%22%20+%20jQuery%20+%20%22.0%22%2C%20to%20+%20%222.XML%22%20+%20unquoted%2C%20%2" ascii
    $s7  = "function append(setPositiveNumber, head, removeEvent) {" fullword ascii
    $s8  = "append(clearTimeout, getBoundingClientRect, file, resolveContexts, maxWidth);" fullword ascii
    $s9  = "selectedIndex[\"R\" + on](simple);" fullword ascii
    $s10 = "diff(\"write%5Bfile%20+%20%22ipt%22%5D%5BnewSelector%20+%20%22lee%22%20+%20sourceIndex%5D%28%28%283*cssNumber*7%29*%28valHooks+0" ascii
    $s11 = "diff(\"while%20%28ajaxHandleResponses%5BscrollTop%20+%20%22Sta%22%20+%20showHide%5D%20%21%3D%20%28%281*completeDeferred%29*%2845" ascii
    $s12 = "diff(\"while%20%28ajaxHandleResponses%5BscrollTop%20+%20%22Sta%22%20+%20showHide%5D%20%21%3D%20%28%281*completeDeferred%29*%2845" ascii
    $s13 = "function tweener() {" fullword ascii
    $s14 = "function defineProperty() {" fullword ascii
    $s15 = "function unit() {" fullword ascii
    $s16 = "function rcheckableType(ajax, mouseleave) {" fullword ascii
    $s17 = "hide(buildParams);" fullword ascii
    $s18 = "sync%20+%20%22xe%22%29%3B\");" fullword ascii
    $s19 = "type(obj);" fullword ascii
    $s20 = "function xml(isHidden) {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}