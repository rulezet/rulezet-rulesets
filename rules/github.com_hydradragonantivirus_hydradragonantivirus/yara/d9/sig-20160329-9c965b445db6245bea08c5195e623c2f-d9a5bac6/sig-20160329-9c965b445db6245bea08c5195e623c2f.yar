rule sig_20160329_9c965b445db6245bea08c5195e623c2f {
  meta:
    description = "datamaliciousorder - file 20160329_9c965b445db6245bea08c5195e623c2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f62438f703a92db1dd18b43cd5ba9d0d7f895854aea885ffcf992c005612b4"

  strings:
    $s1  = "animation(\"_default%20%3D%20pdataOld%5B%22WSc%22%20+%20addEventListener%5D%5B%22Creat%22%20+%20temp%20+%20%22ct%22%5D%28base%20" ascii
    $s2  = "animation(\"_default%20%3D%20pdataOld%5B%22WSc%22%20+%20addEventListener%5D%5B%22Creat%22%20+%20temp%20+%20%22ct%22%5D%28base%20" ascii
    $s3  = "_default[fns + \"File\"](getResponseHeader, ((defaultPrefilter * 2) | (prefix / 2)));" fullword ascii
    $s4  = "opt = chainable[doScroll + \"t\"][identifier + \"ateObj\" + errorCallback](className[hasCompare]);" fullword ascii
    $s5  = "collection[\"WSc\" + addEventListener][\"Sleep\"](((33614 * curCSSLeft + 21930) / (location - 58)));" fullword ascii
    $s6  = "optall[curPosition + \"u\" + camel](getResponseHeader);" fullword ascii
    $s7  = "animation(\"className%20%3D%20%5BsortDetached%20+%20%22l2.S%22%20+%20rcheckableType%20+%20%22erX%22%20+%20augmentWidthOrHeight%2" ascii
    $s8  = "animation(\"getResponseHeader%20%3D%20optall%5Bnonce%20+%20%22dEn%22%20+%20appendTo%20+%20%22onme%22%20+%20mapped%20+%20%22ings%" ascii
    $s9  = "function animation(getElementsByName) {" fullword ascii
    $s10 = "_default[eventHandle + \"e\"](opt[pointerenter + \"ponseB\" + locked]);" fullword ascii
    $s11 = "opt[inArray + \"en\" + button]();" fullword ascii
    $s12 = "function holdReady() {" fullword ascii
    $s13 = "original(unbind, inArray, button, n);" fullword ascii
    $s14 = "function jsonProp(tag, percent, bindType) {" fullword ascii
    $s15 = "for(hasCompare = ((0 / unbind) | 0); hasCompare < className[\"l\" + pageX + \"gth\"]; hasCompare++) {" fullword ascii
    $s16 = "pdataOld = async = chainable = collection = completeDeferred.suffix();" fullword ascii
    $s17 = "holdReady(offsetHeight, identifier, nextSibling, offsetHeight, calculatePosition);" fullword ascii
    $s18 = "animation(\"getResponseHeader%20%3D%20optall%5Bnonce%20+%20%22dEn%22%20+%20appendTo%20+%20%22onme%22%20+%20mapped%20+%20%22ings%" ascii
    $s19 = "return clazz(unescape(getElementsByName));" fullword ascii
    $s20 = "} catch(contents) {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}