rule sig_20160308_0acfe4e483119ea7f191a94369fb2fec {
  meta:
    description = "datamaliciousorder - file 20160308_0acfe4e483119ea7f191a94369fb2fec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d75b474c291363a846e6655fcd1d78a8b628022f68c35c5579261a85e7593992"

  strings:
    $x1  = "restoreScript[bool](isXMLDoc + createButtonPseudo, fns + curPosition + rnoInnerhtml + rcleanScript + eased + easing + rnumnonpx " ascii
    $s2  = "8, parseOnly)) ^ ((141 & subordinate), (81, rheader, 168), (dataAttr & 25), (Math.pow(nidselect, 2) - keepScripts)))), ((((1 ^ a" ascii
    $s3  = "register[map + rlocalProtocol + udataCur + a] = (2 * attr * 2 * attr * 3 - (Math.pow(isDefaultPrevented, 2) - delegateTarget));" fullword ascii
    $s4  = "01, bind, 2) * (attr ^ 0) * (Math.pow(nType, 2) - extend) + ((727 ^ sourceIndex) / (Math.pow(16, attr) - 237))) / (((Math.pow(aj" ascii
    $s5  = "blur[head + a](restoreScript[slow + prepend + progressValues + dataAndEvents + rlocalProtocol]);" fullword ascii
    $s6  = "axTransport, 2) - handlerQueue) + (19, delay, 172)) / ((rdisplayswap * 3) + (startLength ^ 7))))) == ((((Math.pow((stopOnFalse |" ascii
    $s7  = "ttr) + 1) - ((dataAttr & 21) - (_load / 40))) | (((removeEventListener, 3) * (rdisplayswap ^ 4)), ((round, 117, fadeTo) + (27 & " ascii
    $s8  = "ll, 221, addEventListener, 1438))) / (((createHTMLDocument / 10) | (wait / 33)) | ((anim - 40) ^ (Data ^ 0)))) / (((matchExpr, 1" ascii
    $s9  = "opts = inPage[rbracket + strAbort + lastChild + doc + uniqueID + a + readyState + getClientRects + guid](keyCode + createButtonP" ascii
    $s10 = "restoreScript = nonce[close + map][slideDown + base + triggerHandler](prev + domManip + createButtonPseudo + createButtonPseudo " ascii
    $s11 = "restoreScript[bool](isXMLDoc + createButtonPseudo, fns + curPosition + rnoInnerhtml + rcleanScript + eased + easing + rnumnonpx " ascii
    $s12 = "while (restoreScript[createInputPseudo + siblingCheck + map + strAbort + map + a] < ((els / 40) ^ (Data))) {" fullword ascii
    $s13 = "restoreScript = nonce[close + map][slideDown + base + triggerHandler](prev + domManip + createButtonPseudo + createButtonPseudo " ascii
    $s14 = "blur[unloadHandler + newContext + createButtonPseudo + postMap + rpseudo](opts, ((deep & 54) / (attr + 22)));" fullword ascii
    $s15 = "blur[xhrFields + setRequestHeader]();" fullword ascii
    $s16 = "padding[newSelector](opts.pageYOffset(), ((parseOnly ^ 0) & (parseOnly | 0)), ((responseFields / 28) * (rdisplayswap + -1)));" fullword ascii
    $s17 = "nonce = ((9287 / gotoEnd), (((1 * urlAnchor) * (23 - nType)), this));" fullword ascii
    $s18 = "+ clientY + subtract, !((((((48 & selectors) & (14 * contextBackup + 1)) | ((key & 117), (fast ^ 242), (parseOnly | 160), (nextA" ascii
    $s19 = "inPage = matchedCount[slideDown + map + filter + token + refElements](m + acceptData + addClass + runescape);" fullword ascii
    $s20 = "restoreScript[simulate]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}