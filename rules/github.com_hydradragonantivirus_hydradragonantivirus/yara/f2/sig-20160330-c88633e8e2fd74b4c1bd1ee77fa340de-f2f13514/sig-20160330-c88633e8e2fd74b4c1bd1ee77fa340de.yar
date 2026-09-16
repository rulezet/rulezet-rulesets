rule sig_20160330_c88633e8e2fd74b4c1bd1ee77fa340de {
  meta:
    description = "datamaliciousorder - file 20160330_c88633e8e2fd74b4c1bd1ee77fa340de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5573ccab856053f692f12087603b56ff5ce9e4594a80499d84fbca23b4eaad16"

  strings:
    $x1  = "eval(unescape([\"rcheckableType&20&3D&20&28&22ript&22&29&3B&20stopOnFalse&20&3D&20&28&22rings&22&29&3B&20settings&20&\", \"3D&20" ascii
    $s2  = "height = postFilter[\"WSc\" + rcheckableType][\"Create\" + load + \"t\"](isLocal[fadeOut]);" fullword ascii
    $s3  = "step[\"Save\" + write + \"e\"](j, (delay * (19 - top)));" fullword ascii
    $s4  = "toggleClass(\"step&20&3D&20postFilter&5BreplaceChild&20+&20&22ript&22&5D&5BrbuggyQSA&20+&20&22Objec&22&20+&20relatedTarget&5D&28" ascii
    $s5  = "toggleClass(\"step&20&3D&20postFilter&5BreplaceChild&20+&20&22ript&22&5D&5BrbuggyQSA&20+&20&22Objec&22&20+&20relatedTarget&5D&28" ascii
    $s6  = "step[removeAttr + \"e\" + isEmptyObject]();" fullword ascii
    $s7  = "step[\"Wr\" + push_native](height[\"resp\" + divStyle + \"ody\"]);" fullword ascii
    $s8  = "step[createElement + \"od\" + wrapMap] = (3 | delay);" fullword ascii
    $s9  = "height[\"s\" + settings + \"d\"]();" fullword ascii
    $s10 = "for (fadeOut = 0; fadeOut < isLocal[\"l\" + teardown]; fadeOut++) {" fullword ascii
    $s11 = "function fadeIn() {" fullword ascii
    $s12 = "function augmentWidthOrHeight() {" fullword ascii
    $s13 = "indirect(optionSet, hasOwn);" fullword ascii
    $s14 = "function originalOptions() {" fullword ascii
    $s15 = "function always(boolHook, old) {" fullword ascii
    $s16 = "function focusin(urlAnchor) {" fullword ascii
    $s17 = "always(to, wrap, fragment, overflowY, each);" fullword ascii
    $s18 = "function abort(defineProperty, prepend, second) {" fullword ascii
    $s19 = "if (height[\"status\"] == ((then / 20) & (curValue / 47))) {" fullword ascii
    $s20 = "augmentWidthOrHeight(wrap, parseHTML, isEmptyObject);" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}