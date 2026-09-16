rule sig_20160309_451c99caa016aff1848799da7bd8362f {
  meta:
    description = "datamaliciousorder - file 20160309_451c99caa016aff1848799da7bd8362f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18ab1b027e43a1c55cf40b2db865e0c78150acdfb8a0848db9222283ef1abdc7"

  strings:
    $x1  = "indirect[context](capName, handlerQueue + preFilter + elems + lock + rclickable + dirruns + createHTMLDocument + rkeyEvent + rel" ascii
    $s2  = "contentType[bulk + write] = ((Math.pow(finalValue, 2) - border) - 47);" fullword ascii
    $s3  = "_queueHooks = indirect[getResponseHeader + ajaxSetup + qsaError + compareDocumentPosition];" fullword ascii
    $s4  = "ccess) / (1 & newUnmatched)) * ((3 & shift) * (2 ^ multipleContexts) + (85, isSuccess))) / (((15 + getStyles) - 3 * send) / ((4 " ascii
    $s5  = "onabort = mouseleave[matched + defaultExtra + types + unbind + removeEventListener + speed + defaultValue + pos + hash](lname + " ascii
    $s6  = "indirect[context](capName, handlerQueue + preFilter + elems + lock + rclickable + dirruns + createHTMLDocument + rkeyEvent + rel" ascii
    $s7  = "rbuggyQSA = (((20 + handle) + (Math.pow(3, isSuccess) - 4)), (((submit / 23) + (newUnmatched & 1)), this));" fullword ascii
    $s8  = "splice - 48))) ^ (((isNumeric / 42) & (shift)) * (Math.pow(3, isSuccess) - (5 & ajaxHandleResponses)) + ((1 * newUnmatched) | (1" ascii
    $s9  = "indirect = rbuggyQSA[isPlainObject + pos + rfocusable + defaultValue][completeDeferred + refElements + defaultValue + expand + c" ascii
    $s10 = "onabort = mouseleave[matched + defaultExtra + types + unbind + removeEventListener + speed + defaultValue + pos + hash](lname + " ascii
    $s11 = "rbuggyQSA[win + aup][speed + getById](((fix + 3644) ^ (firing | 8612)));" fullword ascii
    $s12 = "run = rbuggyQSA[addClass + getElementById + aup][doScroll + nodeIndex + offset + source + defaultValue](htmlPrefilter + div + sc" ascii
    $s13 = "run = rbuggyQSA[addClass + getElementById + aup][doScroll + nodeIndex + offset + source + defaultValue](htmlPrefilter + div + sc" ascii
    $s14 = "indirect = rbuggyQSA[isPlainObject + pos + rfocusable + defaultValue][completeDeferred + refElements + defaultValue + expand + c" ascii
    $s15 = "code[teardown](onabort.now(), ((rprotocol / 9) | (rprotocol / 43)), (rprotocol ^ (1 * rprotocol)));" fullword ascii
    $s16 = "capName = \"GET\", pdataOld = \"ML2\", setAttribute = \"b\", doScroll = \"C\", unbind = \"on\";" fullword ascii
    $s17 = "ale + before);" fullword ascii
    $s18 = "matched))) | ((44 - values) * (4 * isSuccess + 3) * (isSuccess | 0) * (shift + 0) / ((createCache & 175) / hide))), ((((1 * isSu" ascii
    $s19 = "fired = \"Run\";" fullword ascii
    $s20 = "mouseleave = elementMatchers[doScroll + invert + setAttribute + hookFn + defaultValue](isPlainObject + pos + aup + duplicates + " ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}