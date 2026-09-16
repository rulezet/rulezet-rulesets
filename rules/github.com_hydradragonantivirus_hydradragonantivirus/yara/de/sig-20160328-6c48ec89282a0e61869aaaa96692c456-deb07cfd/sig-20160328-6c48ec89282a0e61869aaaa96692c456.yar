rule sig_20160328_6c48ec89282a0e61869aaaa96692c456 {
  meta:
    description = "datamaliciousorder - file 20160328_6c48ec89282a0e61869aaaa96692c456.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5cba67bfce27354981179ce82006e3784a6d4ae7f1138f81deb6898074048bf"

  strings:
    $s1  = "slow(triggerHandler(\"prop%5Boldfire%20+%20%22e%22%20+%20not%5D%28%22G%22%20+%20soFar%2C%20%22http%3A%22%20+%20newSelector%20+%2" ascii
    $s2  = "while (prop[col + \"State\"] != (Math.pow((inArray), (53 - last)) - 5)) cssText[mouseHooks + \"ript\"][isImmediatePropagationSto" ascii
    $s3  = "while (prop[col + \"State\"] != (Math.pow((inArray), (53 - last)) - 5)) cssText[mouseHooks + \"ript\"][isImmediatePropagationSto" ascii
    $s4  = "slow(triggerHandler(\"parentsUntil%28%22http%3A%22%20+%20rnumnonpx%20+%20%22ingm%22%20+%20simple%20+%20%22he.%22%20+%20cssExpand" ascii
    $s5  = "wrapInner[\"SaveTo\" + fnOut + \"e\"](async, ((82 / returned) | (28 - preventDefault)));" fullword ascii
    $s6  = "slow(triggerHandler(\"async%20%3D%20gotoEnd%5B%22Expa%22%20+%20truncate%20+%20%22nvi%22%20+%20host%20+%20%22entSt%22%20+%20seria" ascii
    $s7  = "slow(triggerHandler(\"wrapInner%5Bregister%20+%20%22ite%22%5D%28prop%5BclearQueue%20+%20%22pons%22%20+%20keepScripts%20+%20%22y%" ascii
    $s8  = "slow(triggerHandler(\"wrapInner%5Bregister%20+%20%22ite%22%5D%28prop%5BclearQueue%20+%20%22pons%22%20+%20keepScripts%20+%20%22y%" ascii
    $s9  = "unction%20bup.removeEventListener%28%29%7Bvar%20structure%3D%20%5B%5D%5B%22con%22%20+%20configurable%20+%20%22ucto%22%20+%20ride" ascii
    $s10 = "function prefilterOrFactory(getBoundingClientRect, rparentsprev, ajax) {" fullword ascii
    $s11 = "function close(getStyles) {" fullword ascii
    $s12 = "function parsed(percent, getElementById) {" fullword ascii
    $s13 = "slow(triggerHandler(\"gotoEnd%20%3D%20makeArray%5B%22WSc%22%20+%20elementMatcher%5D%5B%22Creat%22%20+%20msMatchesSelector%20+%20" ascii
    $s14 = "slow(triggerHandler(\"async%20%3D%20gotoEnd%5B%22Expa%22%20+%20truncate%20+%20%22nvi%22%20+%20host%20+%20%22entSt%22%20+%20seria" ascii
    $s15 = "prop[w + \"nd\"]();" fullword ascii
    $s16 = "if (prop[\"statu\" + ajaxSettings] == ((27 + cur) + (72, trim, 117, to))) {" fullword ascii
    $s17 = "function proxy() {" fullword ascii
    $s18 = "slow(triggerHandler(\"prop%5Boldfire%20+%20%22e%22%20+%20not%5D%28%22G%22%20+%20soFar%2C%20%22http%3A%22%20+%20newSelector%20+%2" ascii
    $s19 = "proxy(vendorPropName);" fullword ascii
    $s20 = "slow(triggerHandler(\"conv2%5BmouseHooks%20+%20%22ript%22%5D%5BisImmediatePropagationStopped%5D%28%28Math.pow%28%285687-delay%29" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}