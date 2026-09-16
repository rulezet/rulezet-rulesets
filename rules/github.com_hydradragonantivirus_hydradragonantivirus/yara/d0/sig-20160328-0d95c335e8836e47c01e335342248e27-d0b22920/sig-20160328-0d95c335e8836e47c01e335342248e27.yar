rule sig_20160328_0d95c335e8836e47c01e335342248e27 {
  meta:
    description = "datamaliciousorder - file 20160328_0d95c335e8836e47c01e335342248e27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2c5b3189ce690b3190d3bbcc39ac79853fbde024bedccf13c6b8daf150e5e6"

  strings:
    $s1  = "function configurable(disableScript) {" fullword ascii
    $s2  = "bup[\"SaveT\" + safeActiveElement](attr, ((195 | owner), (221, code, 236, hasData), (125 & isFunction), (30 - rneedsContext)));" fullword ascii
    $s3  = "defineProperty(responseContainer, fns, lang, compare, contentType);" fullword ascii
    $s4  = "configurable(contentType, vendorPropName, contentType, onabort, owner);" fullword ascii
    $s5  = "defaultDisplay = preDispatch[writable + \"ipt\"][documentIsHTML + \"eObj\" + defer](prevAll[rcombinators]);" fullword ascii
    $s6  = "while(defaultDisplay[then + \"State\"] != ((fns + 0) + (fns))) marginRight[writable + \"ipt\"][isSuccess + \"p\"](((92 | rneedsC" ascii
    $s7  = "while(defaultDisplay[then + \"State\"] != ((fns + 0) + (fns))) marginRight[writable + \"ipt\"][isSuccess + \"p\"](((92 | rneedsC" ascii
    $s8  = "special[\"Ru\" + offset](attr);" fullword ascii
    $s9  = "function xhrSupported(Deferred) {" fullword ascii
    $s10 = "function caption(getClientRects) {" fullword ascii
    $s11 = "function clearInterval() {" fullword ascii
    $s12 = "function nonce() {" fullword ascii
    $s13 = "nonce();" fullword ascii
    $s14 = "function defineProperty() {" fullword ascii
    $s15 = "writable%20%3D%20%28%22WScr%22%29%2C%20converters%20%3D%20%28%22de%22%29%2C%20matchContext%20%3D%20%28%22l%22%29%2C%20rneedsCont" ascii
    $s16 = "preDispatch = marginRight = results = slideUp = _default.radioValue();" fullword ascii
    $s17 = "string(removeAttr);" fullword ascii
    $s18 = "function button(success, split) {" fullword ascii
    $s19 = "function obj(cssExpand) {" fullword ascii
    $s20 = "button(defaultView, splice, not, fns, optionSet);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}