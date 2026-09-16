rule sig_20160325_6d3dcea725ff6cb5bf7cd9b454e73e22 {
  meta:
    description = "datamaliciousorder - file 20160325_6d3dcea725ff6cb5bf7cd9b454e73e22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3d6b2f7db6dd8727c9bccac1d3075f2d3a3c814a4ec0e871a6736c201f0ac26"

  strings:
    $s1  = "src = node = crossDomain = currentTarget = origType.curCSS();" fullword ascii
    $s2  = "lang(traditional, removeEventListener, removeEventListener, rnoContent, evt);" fullword ascii
    $s3  = "function isArray(styles, fromCharCode, postFilter, triggerHandler) {" fullword ascii
    $s4  = "onload = (function origType() {}, \".Shell\");" fullword ascii
    $s5  = "parseOnly[next + \"nd\"]();" fullword ascii
    $s6  = "   defaultDisplay = new src[\"Active\" + rheader + \"jec\" + swap](\"ADO\" + prop + \"eam\");" fullword ascii
    $s7  = "percent = elementMatcher[\"Expan\" + reject + \"onmen\" + dataAttr + \"gs\"](push_native + \"%/\") + timeoutTimer + \"dy\" + rsu" ascii
    $s8  = "percent = elementMatcher[\"Expan\" + reject + \"onmen\" + dataAttr + \"gs\"](push_native + \"%/\") + timeoutTimer + \"dy\" + rsu" ascii
    $s9  = "function ridentifier(propHooks, preFilters, fromCharCode, ajaxSetup) {" fullword ascii
    $s10 = "prop = \"DB.Str\";" fullword ascii
    $s11 = "function removeAttr() {" fullword ascii
    $s12 = "function stopImmediatePropagation() {" fullword ascii
    $s13 = "function lang() {" fullword ascii
    $s14 = "function pixelPosition() {" fullword ascii
    $s15 = "function delay() {" fullword ascii
    $s16 = "function special() {" fullword ascii
    $s17 = "swap = \"t\";" fullword ascii
    $s18 = "function obj() {" fullword ascii
    $s19 = "function nextAll() {" fullword ascii
    $s20 = "function jQuery() {" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}