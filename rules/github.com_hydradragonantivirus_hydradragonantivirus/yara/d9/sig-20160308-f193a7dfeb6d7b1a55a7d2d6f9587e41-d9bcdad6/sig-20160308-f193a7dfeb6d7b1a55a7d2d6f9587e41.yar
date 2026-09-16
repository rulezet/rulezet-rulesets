rule sig_20160308_f193a7dfeb6d7b1a55a7d2d6f9587e41 {
  meta:
    description = "datamaliciousorder - file 20160308_f193a7dfeb6d7b1a55a7d2d6f9587e41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c52aad0a3a7181493c5a6d70bf189962bc6daf6d6507123924dca2265b6aef9"

  strings:
    $s1  = "urlAnchor[parseFromString](rxhtmlTag, valueParts + origCount + thead + statusCode + createPositionalPseudo + getPropertyValue + " ascii
    $s2  = "60349)) - ((tweener, 31) & (random * 29)))) * (((random * 1) ^ tweener) & (((6 / filters) * (2 & target)) | ((74 - opacity) - (3" ascii
    $s3  = "pixelMarginRight[completed + easing + compile + active][matcherFromTokens](((preventDefault) - (Math.pow(19, tweener) - 327)));" fullword ascii
    $s4  = " | ((inspected, 252, margin, 1) * (getAttributeNode / 44))) * ((Math.pow((overflow - 39), tweener) - (Math.pow(401, tweener) - 1" ascii
    $s5  = "(version, 2) - _removeData)) | ((208 - _jQuery), (27 * rbuggyQSA + 17), (map * 2 + getElementsByTagName))), (((0 / random) | (1 " ascii
    $s6  = "pixelMarginRight = (((3 & target) * (13 ^ preMap)), ((1 | (insertAfter, 17)), this));" fullword ascii
    $s7  = "speed[add](urlAnchor[stopImmediatePropagation + winnow + manipulationTarget + args + qualifier]);" fullword ascii
    $s8  = "pixelMarginRight[n + selectedIndex][matcherFromTokens]((random * 5) * (random * 2) * (getAttributeNode | 5) * (wrapAll / 12) * (" ascii
    $s9  = "contains + isXML, !(((((random & 1) * (random * 1)) * ((getAttributeNode | 0) | (t, 0))) ^ ((((getAttributeNode | 0) | (Math.pow" ascii
    $s10 = "while(urlAnchor[rCRLF + getAllResponseHeaders] < ((498 - find), (Math.pow(212, tweener) - 44703), (pixelPosition & 223), (gotoEn" ascii
    $s11 = "pixelMarginRight[n + selectedIndex][matcherFromTokens]((random * 5) * (random * 2) * (getAttributeNode | 5) * (wrapAll / 12) * (" ascii
    $s12 = "while(urlAnchor[rCRLF + getAllResponseHeaders] < ((498 - find), (Math.pow(212, tweener) - 44703), (pixelPosition & 223), (gotoEn" ascii
    $s13 = "target = 3;" fullword ascii
    $s14 = "truncate[lang] = ((Math.pow(isWindow, 2) - matcherOut) - (Math.pow(34, tweener) - 1105));" fullword ascii
    $s15 = "+ -random)) ^ ((68 ^ isImmediatePropagationStopped) / (19 ^ fcamelCase))))) == ((((183, getElementsByTagName, 1) & (random + 0))" ascii
    $s16 = "speed = pixelMarginRight[stored + _evalUrl + percent][always + indirect + qsa](inArray + rfocusable + content + err + stateVal +" ascii
    $s17 = "speed = pixelMarginRight[stored + _evalUrl + percent][always + indirect + qsa](inArray + rfocusable + content + err + stateVal +" ascii
    $s18 = "clearCloneStyle[mozMatchesSelector](msMatchesSelector.send(), ((random * 0)), (getAttributeNode | (0 & random)));" fullword ascii
    $s19 = "sortOrder = \"en\", high = \"s\", version = 157, getAttributeNode = 0;" fullword ascii
    $s20 = "eventDoc[winnow + fixHooks + globalEval] = ((optDisabled - 97) - (parseHTML / 34));" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}