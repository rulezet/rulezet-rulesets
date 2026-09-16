rule sig_20160308_5d52a790d2b8cc15c43fb1d64cca1550 {
  meta:
    description = "datamaliciousorder - file 20160308_5d52a790d2b8cc15c43fb1d64cca1550.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaabfe663ec9e7ec3cd7bfc99fdd7d2d248fed0560ea05aca5eb743fd39df3d0"

  strings:
    $s1  = "argument[parentOffset](crossDomain, preexisting + minWidth + readyState + rkeyEvent + hash + newCache + isHidden + val, !(suffix" ascii
    $s2  = "argument[parentOffset](crossDomain, preexisting + minWidth + readyState + rkeyEvent + hash + newCache + isHidden + val, !(suffix" ascii
    $s3  = "host[startTime](initialInUnit.raw(), ((firstDataType | 0) | (b * 0)), ((rcheckableType, 180, b) & 0));" fullword ascii
    $s4  = "argument = not[contentDocument + overflowY][nodeValue + checkDisplay + hover](sortDetached + createOptions + holdReady + evt + f" ascii
    $s5  = "argument = not[contentDocument + overflowY][nodeValue + checkDisplay + hover](sortDetached + createOptions + holdReady + evt + f" ascii
    $s6  = "not = (((72 ^ arr) - (36 * suffix + 4)), ((Math.pow((rdashAlpha & 6), (b * 2)) - (opts & 29)), this));" fullword ascii
    $s7  = " < ((((5 + disabled) - (159, bubbleType, 23)) + (((b + 0) * (firstDataType / 36)) ^ ((Math.pow(arg, 2) - delegateCount) - (151, " ascii
    $s8  = "matcher[multipleContexts + props + curTop] = ((238 & getter), (205 + ajaxHandleResponses), (143 & checkContext), (1 * firstDataT" ascii
    $s9  = "matcher[multipleContexts + props + curTop] = ((238 & getter), (205 + ajaxHandleResponses), (143 & checkContext), (1 * firstDataT" ascii
    $s10 = "rkeyEvent = \"c-\", pattern = \"ect\", isTrigger = \"Body\", css = 10;" fullword ascii
    $s11 = "not[parsed + offsetParent + overflowY][load + offsetParent](((attrHandle, 88, find, 16906) - Deferred * 2));" fullword ascii
    $s12 = "filter = not[unique + computeStyleTests + currentValue];" fullword ascii
    $s13 = "while (argument[computeStyleTests + flag + width] < ((push_native + 37), (responseText + 85), (pseudos & 7))) {" fullword ascii
    $s14 = "subtract = \"get\";" fullword ascii
    $s15 = "getter = 171;" fullword ascii
    $s16 = "host = disable;" fullword ascii
    $s17 = "initialInUnit = disable[last + createDocumentFragment + nextSibling + els + overflowY + defer + submit](sort + constructor) + ti" ascii
    $s18 = "not[parsed + box][propFilter + parentWindow](((setDocument ^ 190), (hidden & 29), (access | 33), (pseudos ^ 96)));" fullword ascii
    $s19 = "meout + leadingRelative + document + subtract + udataCur;" fullword ascii
    $s20 = " (10 / css)) / (3 & suffix) * 7)))));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}