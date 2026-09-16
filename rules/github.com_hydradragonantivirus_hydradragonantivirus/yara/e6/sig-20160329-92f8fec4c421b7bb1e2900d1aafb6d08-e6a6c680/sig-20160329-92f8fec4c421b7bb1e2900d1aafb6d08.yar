rule sig_20160329_92f8fec4c421b7bb1e2900d1aafb6d08 {
  meta:
    description = "datamaliciousorder - file 20160329_92f8fec4c421b7bb1e2900d1aafb6d08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341738ec10b83bd8ed08d589d23a20438ab2bdad3dde1ba9caff3cff03d4ec26"

  strings:
    $s1  = "bindType = swap[\"WScrip\" + handlers][\"Creat\" + s + \"t\"](parsed[rheaders]);" fullword ascii
    $s2  = "rdashAlpha[curCSS + \"pt\"][allTypes + \"p\"](((1038 + rlocalProtocol) / (22 / script)));" fullword ascii
    $s3  = "pointerenter[invert + \"oFi\" + fx](copy, ((2 + rcomma) & (96, overflowY)));" fullword ascii
    $s4  = "clientX(\"while%20%28bindType%5Bdiv%20+%20%22ySt%22%20+%20option%5D%20%21%3D%20%28%281+overflowY%29%7C%281%26rcomma%29%29%29%20r" ascii
    $s5  = "function qsa(createFxNow, height, head) {" fullword ascii
    $s6  = "function contentDocument(parts) {" fullword ascii
    $s7  = "clearQueue[\"Ru\" + startTime](copy);" fullword ascii
    $s8  = "onerror(to, invert);" fullword ascii
    $s9  = "clientX(\"while%20%28bindType%5Bdiv%20+%20%22ySt%22%20+%20option%5D%20%21%3D%20%28%281+overflowY%29%7C%281%26rcomma%29%29%29%20r" ascii
    $s10 = "clientX(\"copy%20%3D%20clearQueue%5B%22Expan%22%20+%20leadingRelative%20+%20%22vir%22%20+%20types%20+%20%22tStrin%22%20+%20check" ascii
    $s11 = "eased(rhtml, ready, selected);" fullword ascii
    $s12 = "function onerror(factory, returnValue) {" fullword ascii
    $s13 = "function rbuggyMatches() {" fullword ascii
    $s14 = "function eased() {" fullword ascii
    $s15 = "percent();" fullword ascii
    $s16 = "function percent() {" fullword ascii
    $s17 = "radioValue[\"WScr\" + prefilterOrFactory][\"Slee\" + isImmediatePropagationStopped](((4809 & duplicates) | (213, self)));" fullword ascii
    $s18 = "function jqXHR(ontype) {" fullword ascii
    $s19 = "rdashAlpha = radioValue = swap = noop = trim.isNumeric();" fullword ascii
    $s20 = "clientX(\"copy%20%3D%20clearQueue%5B%22Expan%22%20+%20leadingRelative%20+%20%22vir%22%20+%20types%20+%20%22tStrin%22%20+%20check" ascii

  condition:
    uint16(0) == 0x616e and
    8 of them
}