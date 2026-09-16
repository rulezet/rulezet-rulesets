rule sig_20160309_bc00a8106e0eb1f9515eb86eb2690891 {
  meta:
    description = "datamaliciousorder - file 20160309_bc00a8106e0eb1f9515eb86eb2690891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b46d66f0e48b087f569e67bab89307015e12e62b43506755d814f1375ae24d1"

  strings:
    $x1  = "cur[eased](after + curElem, removeData + promise + processData + oMatchesSelector + newUnmatched + delegateType + click + eventD" ascii
    $s2  = "PI = \"oFi\", disableScript = \"WS\", next = 13, curCSSLeft = \"%TEMP%\";" fullword ascii
    $s3  = "0 ^ get) - (98 - write)) + (Math.pow((5 & rdashAlpha), (154, elementMatchers, 2)) - (firstDataType + 9)))) - ((((backgroundClip " ascii
    $s4  = "cur[eased](after + curElem, removeData + promise + processData + oMatchesSelector + newUnmatched + delegateType + click + eventD" ascii
    $s5  = "+ 250) / (newContext - 25)) | ((memory, 88, offsetHeight) | (25 - conv2))) | ((1 + (onerror, 235, eventPath)) * ((76 ^ hash), (1" ascii
    $s6  = "nodeValue[isReady + offsetParent + forward + inspect] = ((1 & body) + 0);" fullword ascii
    $s7  = "splice = protocol[disableScript + globalEventContext][once + hover + insertBefore + inspect + dataFilter](ontype + to + optgroup" ascii
    $s8  = "splice = protocol[disableScript + globalEventContext][once + hover + insertBefore + inspect + dataFilter](ontype + to + optgroup" ascii
    $s9  = "protocol[nextAll + anim + getBoundingClientRect][one](((16093 & innerText) & (706192 / write)));" fullword ascii
    $s10 = "get = 40, conv2 = 25, nodeIndex = \"s\", inspect = \"e\", innerText = 16315, parentsUntil = \"Run\";" fullword ascii
    $s11 = "handlerQueue[matchAnyContext](box.doScroll(), (0 / (next - 5)), ((arr - 8)));" fullword ascii
    $s12 = "cur = protocol[result + forward + isReady][abort + inspected + jsonpCallback + wait + isReady](elements + toggleClass + host);" fullword ascii
    $s13 = "box = appendChild[which + isHidden + statusCode + rmultiDash + run + isSuccess + opacity + conv + strAbort](curCSSLeft + hold) +" ascii
    $s14 = "box = appendChild[which + isHidden + statusCode + rmultiDash + run + isSuccess + opacity + conv + strAbort](curCSSLeft + hold) +" ascii
    $s15 = "onerror = 33, run = \"ronme\", i = \"ject\", hold = \"/\";" fullword ascii
    $s16 = "attrs = \"w\", unwrap = \"Bo\", host = \"TP\", mozMatchesSelector = \"dy\", options = 4512;" fullword ascii
    $s17 = "var forward = \"p\"," fullword ascii
    $s18 = "appendChild = valueParts[len + pageX + i](tweener + animate + clearInterval);" fullword ascii
    $s19 = "splice[origName + rpseudo]();" fullword ascii
    $s20 = " nodeIndex + rtypenamespace + size + currentValue;" fullword ascii

  condition:
    uint16(0) == 0x706f and
    1 of ($x*) and 4 of them
}