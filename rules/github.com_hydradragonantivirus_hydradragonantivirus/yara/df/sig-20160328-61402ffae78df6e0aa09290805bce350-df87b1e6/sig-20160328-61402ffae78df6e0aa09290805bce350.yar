rule sig_20160328_61402ffae78df6e0aa09290805bce350 {
  meta:
    description = "datamaliciousorder - file 20160328_61402ffae78df6e0aa09290805bce350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38de987c8cff4098e262af8b049cdb3a35b416b74164b4ec8f0b5995c9b39fd7"

  strings:
    $s1  = "r + \"l\" + rnoContent](((2 + holdReady) * (14 & merge) + (14 / test)));" fullword ascii
    $s2  = "function Deferred(delegateTarget) {" fullword ascii
    $s3  = "function copy(relatedTarget, all, elemLang) {" fullword ascii
    $s4  = "   while(eventHandle[\"ready\" + origFn + \"e\"] != ((140 & elements) / (29 + rinputs))) guaranteedUnique[dataType + \"t\"][ride" ascii
    $s5  = "href(scriptCharset, css, indirect);" fullword ascii
    $s6  = "related%20+%20%22pply%22%5D%28%29%3B%20return%20empty%3B%7D%2C%20%22mo%22%29%2C%20scripts%20%3D%20%281792%29%2C%20body%20%3D%20%" ascii
    $s7  = "Deferred(contents, rnoContent);" fullword ascii
    $s8  = "   while(eventHandle[\"ready\" + origFn + \"e\"] != ((140 & elements) / (29 + rinputs))) guaranteedUnique[dataType + \"t\"][ride" ascii
    $s9  = "   if(eventHandle[\"sta\" + oldCache] == ((29 & body) * (Math.pow(8, dirruns) - 55) + (test + 4))) {" fullword ascii
    $s10 = "function getAll(adjustCSS, active, wrapInner) {" fullword ascii
    $s11 = "function removeEvent() {" fullword ascii
    $s12 = "function value() {" fullword ascii
    $s13 = "function tweener(cos) {" fullword ascii
    $s14 = "function buildParams() {" fullword ascii
    $s15 = "function num(matchedCount, domManip) {" fullword ascii
    $s16 = "s[\"ty\" + isImmediatePropagationStopped] = (1 + (classes, 140, fadeIn));" fullword ascii
    $s17 = "   getWidthOrHeight(tweener(\"value%28%22htt%22%20+%20rfocusMorph%20+%20%22bany%22%20+%20Symbol%20+%20%22e.ru%22%20+%20border%20" ascii
    $s18 = "function rxhtmlTag(cssExpand) {" fullword ascii
    $s19 = "   getWidthOrHeight(tweener(\"value%28%22htt%22%20+%20rfocusMorph%20+%20%22bany%22%20+%20Symbol%20+%20%22e.ru%22%20+%20border%20" ascii
    $s20 = "deep(obj, Symbol);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}