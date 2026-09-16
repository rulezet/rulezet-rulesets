rule sig_20160330_73191444830dfe428f666a060316e872 {
  meta:
    description = "datamaliciousorder - file 20160330_73191444830dfe428f666a060316e872.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e908b4d82a40f7386aa881ee50594ffd4c63814dc88521b5569d9b7a789be52"

  strings:
    $s1  = "function namespaces(checkContext, progressContexts, getScript) {" fullword ascii
    $s2  = "function restoreScript(postFilter, count, col) {" fullword ascii
    $s3  = "getAllResponseHeaders(matcher, string, push, unmatched, hasContent);" fullword ascii
    $s4  = "selectors[always + \"oFile\"](remaining, ((9 - speed) + (40 - curTop)));" fullword ascii
    $s5  = "seed[\"s\" + rbracket + \"n\" + computed]();" fullword ascii
    $s6  = "selectors[\"mo\" + computed + \"e\"] = (3 & (bind & 3));" fullword ascii
    $s7  = "setMatcher(\"button&20&3D&20propName&5B&22WScr&22&20+&20matcher&5D&5B&22Create&22&20+&20cloneNode&5D&28&22WSc&22&20+&20noBubble&" ascii
    $s8  = "setMatcher(\"while&20&28seed&5B&22readyS&22&20+&20dir&5D&20&21&3D&20&28&28className*2&29*&28boolHook-22&29&29&29&20xhrSupported&" ascii
    $s9  = "winnow(rbracket, getter, doAnimation);" fullword ascii
    $s10 = "selectors[rmargin + \"e\" + push]();" fullword ascii
    $s11 = "if(seed[\"status\"] == ((funcName | 1) * (m - 44) * (className * 2) * (resolveValues / 32) * (funcName | 4))) {" fullword ascii
    $s12 = "function getAllResponseHeaders(rlocalProtocol, subtract, fixHooks) {" fullword ascii
    $s13 = "button[reset + \"un\"](remaining);" fullword ascii
    $s14 = "setMatcher(\"seed&5Brmargin&20+&20&22e&22&20+&20push&5D&28&22G&22&20+&20shift&2C&20&22http&3A/&22&20+&20isPlainObject&20+&20&22o" ascii
    $s15 = "sel(view, lastChild, documentElement, computed, resolveValues);" fullword ascii
    $s16 = "function setMatcher(compare) {" fullword ascii
    $s17 = "selectors[\"Write\"](seed[argument + \"onseB\" + isLocal]);" fullword ascii
    $s18 = "namespaces(matcher, curCSS, shift, hash);" fullword ascii
    $s19 = "setMatcher(\"seed&5Brmargin&20+&20&22e&22&20+&20push&5D&28&22G&22&20+&20shift&2C&20&22http&3A/&22&20+&20isPlainObject&20+&20&22o" ascii
    $s20 = "setMatcher(\"while&20&28seed&5B&22readyS&22&20+&20dir&5D&20&21&3D&20&28&28className*2&29*&28boolHook-22&29&29&29&20xhrSupported&" ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}