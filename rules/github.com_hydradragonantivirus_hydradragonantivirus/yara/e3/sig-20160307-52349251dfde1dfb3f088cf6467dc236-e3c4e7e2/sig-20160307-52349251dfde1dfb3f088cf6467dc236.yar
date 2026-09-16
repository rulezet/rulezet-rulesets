rule sig_20160307_52349251dfde1dfb3f088cf6467dc236 {
  meta:
    description = "datamaliciousorder - file 20160307_52349251dfde1dfb3f088cf6467dc236.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44e0d569b4b4b69dee70694e0bc61dc707457d93a45485058974e223f9cce376"

  strings:
    $x1  = "clearTimeout[overflowX + ajaxPrefilter](buildFragment + copyIsArray, removeEventListener + write + rpseudo + innerText + support" ascii
    $s2  = "clearTimeout = iframe[setDocument + addGetHookIf + namespace][optall + restoreScript + width](onerror + newSelector + clientX + " ascii
    $s3  = "unique = iframe[round + first][optall + selectors + version + namespace](submit + currentTarget + isXMLDoc + node);" fullword ascii
    $s4  = "iframe = ((506 / fnOver) * (11 + readyList), (((245 / getElementsByTagName) * (21 - resolveValues) + (1 + strAbort)), this));" fullword ascii
    $s5  = "clearTimeout = iframe[setDocument + addGetHookIf + namespace][optall + restoreScript + width](onerror + newSelector + clientX + " ascii
    $s6  = "   iframe[setDocument + responseHeadersString][response + dispatch](((Math.pow(3, strAbort) - 5) | (v, 12, prevAll)));" fullword ascii
    $s7  = "rt / 50) ^ (module - 83)), ((Math.pow(stopped, 2) - keys) / (16 | uniqueSort)), (0 | (removeEvent ^ 1)))) | (((hasFocus ^ 1) / (" ascii
    $s8  = ", 2) - operator)) ^ ((86 * rcssNum + 81) & (trim | 341))) / (((cors ^ 0) * (cors + 0)) + responseType * (2 & responseType) * 2))" ascii
    $s9  = " + high + prototype, !((((((99, insertAfter, 156, getAttributeNode) | (244 - getText)), ((2, cors) * 1)) - ((setup | 1), ((onabo" ascii
    $s10 = "while (clearTimeout[cssHooks + div1 + jQuery] < ((Math.pow(groups, 2) - collection), 2 * strAbort)) {" fullword ascii
    $s11 = "root - 7)) ^ (removeEvent / 34))) == ((((on & 254), (startLength / 35)), (strAbort * 2 ^ (push, 5, responseType))) * (((57, optD" ascii
    $s12 = "iframe[els + rxhtmlTag][response + memory + isTrigger](((114688 | msFullscreenElement) / (47 - triggered)));" fullword ascii
    $s13 = "defer)) / ((26 & firstChild) ^ (139 - prevObject))) / (((Math.pow((Math.pow(35, strAbort) - 1179), (strAbort + 0)) - (Math.pow(a" ascii
    $s14 = "isabled, 149, hasFocus) - (1 * rbuggyQSA)) & ((1 * responseType) | (1 & removeEvent))) * (((120, trim, 180, byElement) + (131 - " ascii
    $s15 = "clearTimeout[overflowX + ajaxPrefilter](buildFragment + copyIsArray, removeEventListener + write + rpseudo + innerText + support" ascii
    $s16 = "ition + fired) + ajaxConvert + dequeue + appendTo + proxy;" fullword ascii
    $s17 = "first = \"pt\", prependTo = \"WScrip\", bind = 13, a = 1942, rhash = \"veT\";" fullword ascii
    $s18 = "preFilters = camelKey[boolHook + parentWindow + tokenCache](prependTo + nonce + fire);" fullword ascii
    $s19 = "var operator = 3769297," fullword ascii
    $s20 = "   select[getBoundingClientRect + namespace + now] = (1 * (sortDetached, 0));" fullword ascii

  condition:
    uint16(0) == 0x706f and
    1 of ($x*) and 4 of them
}