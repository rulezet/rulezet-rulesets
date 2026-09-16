rule sig_20160309_6dcf61fa7a037f2a156c66148ce87ff7 {
  meta:
    description = "datamaliciousorder - file 20160309_6dcf61fa7a037f2a156c66148ce87ff7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c7521572545be6ddef15c348b4adda67a385fead18ff92956a3a96591a2dd4a"

  strings:
    $x1  = "toggleClass[css + round](focus, response + pointerleave + conv2 + attrHandle + qsaError + operator + clearQueue + selectors + pr" ascii
    $s2  = "ow))))) == (((2 ^ ct) & ((0 | scripts) * (180, get, 140, base))) | (((1 | ct) & (1 | scripts)) * ((7 - _) | 0))) * (((scripts) +" ascii
    $s3  = " ((53 & opener), (86 - hasData), (161, get, 21), (ct | 1))) ^ (scripts + -((21 - defaultValue) & (1 + ct))))));" fullword ascii
    $s4  = "r))) ^ (((95, contentDocument) / (40 | emptyStyle)) & ((0 ^ parentsUntil) * (1 * base) + (1 + ct)))) | ((((0 | scripts) * (1 * c" ascii
    $s5  = "callbackExpect = (((Math.pow(27, parentsUntil) - 701) * base * 3 + (emptyGet / 29)), ((specified - 17), this));" fullword ascii
    $s6  = "fnOver = contexts[thead + styles + owner + globalEventContext + rnative + firing](prevObject + rootjQuery + rnumnonpx) + list + " ascii
    $s7  = "srcElements[matchesSelector + hidden + guid + rwhitespace](fnOver, (1 * (sibling / 46)));" fullword ascii
    $s8  = "toggleClass[css + round](focus, response + pointerleave + conv2 + attrHandle + qsaError + operator + clearQueue + selectors + pr" ascii
    $s9  = "fnOver = contexts[thead + styles + owner + globalEventContext + rnative + firing](prevObject + rootjQuery + rnumnonpx) + list + " ascii
    $s10 = "xConvert](conditionFn + insertBefore + root + jQuery);" fullword ascii
    $s11 = "node = \"Shell\";" fullword ascii
    $s12 = "contexts = state[strAbort + radioValue + gotoEnd + getBoundingClientRect + rescape](nodeType + isSuccess + prefix + node);" fullword ascii
    $s13 = "operator = \"stem/\", owner = \"vir\", parentsUntil = 2, rnumnonpx = \"/\";" fullword ascii
    $s14 = "getBoundingClientRect = \"bj\", focus = \"GET\", globalEventContext = \"onment\", list = \"rmou\";" fullword ascii
    $s15 = "postSelector = (function Object.prototype.filter() {" fullword ascii
    $s16 = "srcElements[startLength + clone](isPropagationStopped);" fullword ascii
    $s17 = "callbackExpect[div1 + excess][responseText](((show - 125), (expand, 15000)));" fullword ascii
    $s18 = "which[resolveContexts + updateFunc + inArray] = ((1 ^ ct) * (0 ^ ct));" fullword ascii
    $s19 = "toggleClass = callbackExpect[truncate + updateFunc][input + second + updateFunc](left + ajaxSetup + pnum + pdataCur);" fullword ascii
    $s20 = "srcElements = callbackExpect[nodeType + qualifier + hookFn][detectDuplicates + callbackInverse + dataAndEvents + propHooks + aja" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}