rule sig_20160329_814266bc1f86173a5b084249608a0665 {
  meta:
    description = "datamaliciousorder - file 20160329_814266bc1f86173a5b084249608a0665.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85696c98f643bfb410b42969c40e847ab2a1f2e495a5b0bfa828c845a98c3b94"

  strings:
    $s1  = "tbody[pdataOld + \"pt\"][load + \"ep\"](((5345 - padding) & (Math.pow(7811, compareDocumentPosition) - 61003633)));" fullword ascii
    $s2  = "if (completed[safeActiveElement + \"s\"] == ((3634 & border) / (22 - teardown))) {" fullword ascii
    $s3  = "function original(target, outermostContext) {" fullword ascii
    $s4  = "scale(\"arg%28%22http%3A%22%20+%20parseHTML%20+%20%22owthel%22%20+%20isDefaultPrevented%20+%20%22com/oQ%22%20+%20toggleClass%20+" ascii
    $s5  = "for (appendTo = (0 / xhr); appendTo < seekingTransport[until + \"ng\" + colgroup]; appendTo++) {" fullword ascii
    $s6  = "scale(\"while%20%28completed%5B%22read%22%20+%20fadeToggle%5D%20%21%3D%20%282+%28speed%2C208%2CcompareDocumentPosition%29%29%29%" ascii
    $s7  = "scale(\"rootjQuery%5BgetJSON%20+%20%22yp%22%20+%20ifModified%5D%20%3D%20%28%282*compareDocumentPosition*2*compareDocumentPositio" ascii
    $s8  = "scale(\"rootjQuery%5BgetJSON%20+%20%22yp%22%20+%20ifModified%5D%20%3D%20%28%282*compareDocumentPosition*2*compareDocumentPositio" ascii
    $s9  = "scale(\"curPosition%20%3D%20anim%5B%22Expand%22%20+%20view%20+%20%22onment%22%20+%20inspectPrefiltersOrTransports%20+%20%22gs%22" ascii
    $s10 = "bind();" fullword ascii
    $s11 = "function rrun(dataTypeExpression) {" fullword ascii
    $s12 = "function bind(checkDisplay, isNumeric, arr) {" fullword ascii
    $s13 = "rrun(until, eq, colgroup);" fullword ascii
    $s14 = "scale(\"seekingTransport%20%3D%20%5Bparsed%20+%20%22.Ser%22%20+%20propFilter%20+%20%22MLHTT%22%20+%20parseFromString%20+%20%22.0" ascii
    $s15 = "scale(\"rootjQuery%5B%22Writ%22%20+%20ifModified%5D%28completed%5B%22res%22%20+%20detectDuplicates%20+%20%22eBod%22%20+%20pnum%5" ascii
    $s16 = "scale(\"while%20%28completed%5B%22read%22%20+%20fadeToggle%5D%20%21%3D%20%282+%28speed%2C208%2CcompareDocumentPosition%29%29%29%" ascii
    $s17 = "scale(\"anim%20%3D%20keyHooks%5B%22WScr%22%20+%20multipleContexts%5D%5B%22Cre%22%20+%20whitespace%20+%20%22Object%22%5D%28pdataO" ascii
    $s18 = "scale(\"arg%28%22http%3A%22%20+%20parseHTML%20+%20%22owthel%22%20+%20isDefaultPrevented%20+%20%22com/oQ%22%20+%20toggleClass%20+" ascii
    $s19 = "scale(\"rootjQuery%5B%22Writ%22%20+%20ifModified%5D%28completed%5B%22res%22%20+%20detectDuplicates%20+%20%22eBod%22%20+%20pnum%5" ascii
    $s20 = "scale(\"seekingTransport%20%3D%20%5Bparsed%20+%20%22.Ser%22%20+%20propFilter%20+%20%22MLHTT%22%20+%20parseFromString%20+%20%22.0" ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}