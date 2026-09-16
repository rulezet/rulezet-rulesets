rule sig_20160329_1c2110b99b1dffdfa5186ad537835d5f {
  meta:
    description = "datamaliciousorder - file 20160329_1c2110b99b1dffdfa5186ad537835d5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebaa0dfbc5e2fc7aabfe864d621cc5ba107e81307b7b89d92f614e6963497bec"

  strings:
    $s1  = "using[\"WScrip\" + disabled][\"Sle\" + target](((868 | divStyle) + (Math.pow(4008, n) - 16059957)));" fullword ascii
    $s2  = "if(handlerQueue[border] == (Math.pow((2013 / isDefaultPrevented), (1 * n)) - (33280 | completeDeferred))) {" fullword ascii
    $s3  = "raw[\"Sav\" + opt + \"ile\"](identifier, ((handleObj - 33) / (arg - 27)));" fullword ascii
    $s4  = "checkClone(\"while%20%28handlerQueue%5B%22readyS%22%20+%20_jQuery%20+%20%22e%22%5D%20%21%3D%20%28%28n*2*n%29/%2831-matcherFromGr" ascii
    $s5  = "pdataOld(iterator, unquoted, getScript, copy, chainable);" fullword ascii
    $s6  = "animation = keyHooks = textContent = using = iframe.onload();" fullword ascii
    $s7  = "raw[\"ty\" + preexisting] = ((progressContexts, 40) - (fragment / 8));" fullword ascii
    $s8  = "handlerQueue[margin + \"en\" + compile]();" fullword ascii
    $s9  = "removeAttr[origName + \"un\"](identifier);" fullword ascii
    $s10 = "checkClone(\"close%28%22http%22%20+%20ready%20+%20%22tart%22%20+%20last%20+%20%22rge.c%22%20+%20isNumeric%20+%20%22k/fR%22%20+%2" ascii
    $s11 = "checkClone(\"close%28%22http%22%20+%20ready%20+%20%22tart%22%20+%20last%20+%20%22rge.c%22%20+%20isNumeric%20+%20%22k/fR%22%20+%2" ascii
    $s12 = "function getText() {" fullword ascii
    $s13 = "function serializeArray(addGetHookIf, defaultView, clientX) {" fullword ascii
    $s14 = "raw[diff + \"d\" + attr] = (168, register, 3);" fullword ascii
    $s15 = "checkClone(\"identifier%20%3D%20removeAttr%5Bwhat%20+%20%22ndEn%22%20+%20cssPrefixes%20+%20%22ment%22%20+%20defaultPrevented%20+" ascii
    $s16 = "race%20+%20%22rosof%22%20+%20src%20+%20%22HTTP%22%5D%3B\");" fullword ascii
    $s17 = "checkClone(\"while%20%28handlerQueue%5B%22readyS%22%20+%20_jQuery%20+%20%22e%22%5D%20%21%3D%20%28%28n*2*n%29/%2831-matcherFromGr" ascii
    $s18 = "outerCache(stateString, head, toggleClass, wait, clientY);" fullword ascii
    $s19 = "function until() {" fullword ascii
    $s20 = "until();" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}