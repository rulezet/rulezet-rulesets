rule sig_20160325_653ba08943c3d726f7f3043f227b5887 {
  meta:
    description = "datamaliciousorder - file 20160325_653ba08943c3d726f7f3043f227b5887.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8134b3403d6c796f5eb46f85080668b94e15d51e51f0b21cce2bb3ce9e51c7e"

  strings:
    $s1  = "script[removeAttr + \"eep\"]((relatedTarget * 2 * relatedTarget * 2 * boxSizingReliableVal * 5 * relatedTarget));" fullword ascii
    $s2  = "setAttribute = \"%TEMP%\";" fullword ascii
    $s3  = "mapped = script[booleans + \"ateO\" + makeArray](\"WScri\" + optionSet + \"ell\");" fullword ascii
    $s4  = "script = nextSibling[\"WSc\" + cssHooks + \"t\"];" fullword ascii
    $s5  = "guaranteedUnique = \"BG.exe\", special = \"ToF\";" fullword ascii
    $s6  = "   responseFields(removeAttr, relatedTarget, cssHooks, success);" fullword ascii
    $s7  = "function defineProperty(requestHeaders, next, protocol, events) {" fullword ascii
    $s8  = "   eval(addClass(\"hash%28closest%20+%20%22onseBo%22%20+%20rkeyEvent%2C%20%28%28Math.pow%2811%2C%20boxSizingReliableVal%29-106%2" ascii
    $s9  = "   eval(addClass(\"hash%28closest%20+%20%22onseBo%22%20+%20rkeyEvent%2C%20%28%28Math.pow%2811%2C%20boxSizingReliableVal%29-106%2" ascii
    $s10 = " linear + \"sc\" + trim;" fullword ascii
    $s11 = "idx = mapped[timeoutTimer + \"Envi\" + hide + \"ment\" + compareDocumentPosition + \"ngs\"](setAttribute + \"/\") + class2type +" ascii
    $s12 = "idx = mapped[timeoutTimer + \"Envi\" + hide + \"ment\" + compareDocumentPosition + \"ngs\"](setAttribute + \"/\") + class2type +" ascii
    $s13 = "function hash(active, rsingleTag, next, outermost) {" fullword ascii
    $s14 = "function addClass(keepScripts) {" fullword ascii
    $s15 = "function gotoEnd() {" fullword ascii
    $s16 = "function self() {" fullword ascii
    $s17 = "function constructor() {" fullword ascii
    $s18 = "constructor();" fullword ascii
    $s19 = "function responseFields() {" fullword ascii
    $s20 = "function fromCharCode() {" fullword ascii

  condition:
    uint16(0) == 0x6968 and
    8 of them
}