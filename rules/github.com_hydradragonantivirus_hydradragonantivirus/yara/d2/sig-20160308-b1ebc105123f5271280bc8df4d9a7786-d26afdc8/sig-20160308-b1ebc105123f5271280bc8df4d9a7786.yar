rule sig_20160308_b1ebc105123f5271280bc8df4d9a7786 {
  meta:
    description = "datamaliciousorder - file 20160308_b1ebc105123f5271280bc8df4d9a7786.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb24d602dac8f1422eb83b25bf44db7ea214f0d78df170a0fcf601e9cc09a39e"

  strings:
    $s1  = "password = modified[fadeOut + clearCloneStyle + resolve][rneedsContext + firstChild + removeEventListener + content](swap + elem" ascii
    $s2  = "password = modified[fadeOut + clearCloneStyle + resolve][rneedsContext + firstChild + removeEventListener + content](swap + elem" ascii
    $s3  = "configurable[rhtml + returnFalse](password[cacheLength + code + getWindow + animation]);" fullword ascii
    $s4  = "password[hidden + elems](_default, fnOut + document + conv2 + visibility + linear + createTextNode + active + dequeue + handleOb" ascii
    $s5  = "readyState = \"%TEMP%\";" fullword ascii
    $s6  = "modified = (((Math.pow(102, split) - 10230), (preexisting), 2 * matchedCount, (Math.pow(54, split) - 2810)), (((root ^ 15) - (st" ascii
    $s7  = "modified[namespace + ready][uid + define]((5 * split * 2 * conditionFn * (Math.pow(3, split) - 5) + (rmultiDash * 2 + slow)));" fullword ascii
    $s8  = "modified = (((Math.pow(102, split) - 10230), (preexisting), 2 * matchedCount, (Math.pow(54, split) - 2810)), (((root ^ 15) - (st" ascii
    $s9  = "_default = \"GET\", rneedsContext = \"C\", removeEventListener = \"bje\", hidden = \"o\";" fullword ascii
    $s10 = "password[hidden + elems](_default, fnOut + document + conv2 + visibility + linear + createTextNode + active + dequeue + handleOb" ascii
    $s11 = "while(password[dataUser + timeoutTimer + mouseleave] < (split * 2 | (fx & 1))) {" fullword ascii
    $s12 = "configurable[location + hidden + getWindow]();" fullword ascii
    $s13 = "modified[namespace + ready][merge + createPositionalPseudo](((fadeToggle | 3200) / (postSelector)));" fullword ascii
    $s14 = "configurable = modified[contexts + keys + triggerHandler + resolve][percent + status + resolve](rbracket + _$ + documentIsHTML);" ascii
    $s15 = "fontWeight = statusText[rneedsContext + sortInput + cssPrefixes + content](fadeOut + resolveContexts + attrHandle + eventPath);" fullword ascii
    $s16 = "status = \"Objec\", createTextNode = \"uis\", href = 177, headers = \"vir\", namespace = \"WScr\", addBack = \"com/o\";" fullword ascii
    $s17 = "password[offsetWidth]();" fullword ascii
    $s18 = "clone = fontWeight[index + trim + cssFn + clearTimeout + headers + trigger + uid + then + invert + callbackExpect](readyState + " ascii
    $s19 = "clone = fontWeight[index + trim + cssFn + clearTimeout + headers + trigger + uid + then + invert + callbackExpect](readyState + " ascii
    $s20 = "createComment[boxSizingReliableVal + camel + invert] = (1 + -(settings / 45));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}