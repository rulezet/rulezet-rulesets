rule sig_20160309_60804a37abd2c7b6fd29da3255416c9b {
  meta:
    description = "datamaliciousorder - file 20160309_60804a37abd2c7b6fd29da3255416c9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a4510968e846f3d20f2af3f4914fe42cc3b9098c37a60bc9e2672483d2c2b0b"

  strings:
    $s1  = "Data * 2))) / (((Math.pow(oldfire, 2) - l) + (2 | oldfire)) & ((16 - computeStyleTests) + (29 - head))) * ((1 ^ (setTimeout * 2)" ascii
    $s2  = "ownerDocument[onload + timers][contentType + originalEvent](((binary | 5191) * (always | 2) + (done - 385)));" fullword ascii
    $s3  = "DOMParser[stateString](sortStable, createInputPseudo + isPlainObject + removeEvent + progress + rejectWith + opt + msMatchesSele" ascii
    $s4  = "returnFalse = \"C\", sortStable = \"GET\", getPropertyValue = \"B.St\", opt = \"c2.com\", simple = \"ion\", cacheLength = \"ipt" ascii
    $s5  = "ready[parents + simple] = ((1 | always) & (1 + -setTimeout));" fullword ascii
    $s6  = "nd + selectors + postFinder + handler;" fullword ascii
    $s7  = "duration = ownerDocument[firstChild + cacheLength][iframe + rbracket + ontype + timers](setGlobalEval + getPropertyValue + throw" ascii
    $s8  = "hover = s[callback + button + class2type + compare + isFunction](uniqueSort + Symbol + fns + uniqueSort + htmlPrefilter) + prepe" ascii
    $s9  = " 25))) + (((doneName * 3 + testContext)), ((255 & access), (164 | remaining)), ((9 + elemData) & (69 - speeds)), ((2 ^ setTimeou" ascii
    $s10 = "ownerDocument = (((404 & srcElements) | (10 | always)), ((2 * (div1 - 26) + (l - 4)), this));" fullword ascii
    $s11 = "binary = 4112, head = 26, uniqueSort = \"%\", curLeft = \"e\", selectors = \"Sele\";" fullword ascii
    $s12 = "duration = ownerDocument[firstChild + cacheLength][iframe + rbracket + ontype + timers](setGlobalEval + getPropertyValue + throw" ascii
    $s13 = "handler = \".scr\";" fullword ascii
    $s14 = "duration[matches + rbuggyQSA](hover, ((1 * elemData) | 0));" fullword ascii
    $s15 = "DOMParser[stateString](sortStable, createInputPseudo + isPlainObject + removeEvent + progress + rejectWith + opt + msMatchesSele" ascii
    $s16 = "DOMParser = ownerDocument[easing + sourceIndex][returnFalse + origType + timers + lang + timers](resolveValues + off + ajaxHandl" ascii
    $s17 = "DOMParser = ownerDocument[easing + sourceIndex][returnFalse + origType + timers + lang + timers](resolveValues + off + ajaxHandl" ascii
    $s18 = "deep = ownerDocument[preventDefault + wrapMap];" fullword ascii
    $s19 = "hover = s[callback + button + class2type + compare + isFunction](uniqueSort + Symbol + fns + uniqueSort + htmlPrefilter) + prepe" ascii
    $s20 = "compare = \"tStri\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}