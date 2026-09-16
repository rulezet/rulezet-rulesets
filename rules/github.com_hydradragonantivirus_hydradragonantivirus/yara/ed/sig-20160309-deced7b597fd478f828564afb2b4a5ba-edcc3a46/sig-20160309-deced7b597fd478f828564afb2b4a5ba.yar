rule sig_20160309_deced7b597fd478f828564afb2b4a5ba {
  meta:
    description = "datamaliciousorder - file 20160309_deced7b597fd478f828564afb2b4a5ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "200a2c8e3e934951cfdb9913c27e0f84a3b9fd9225f9381f93070b2ded2d6acc"

  strings:
    $s1  = "specified = div[attrs + defaultView][content + rscriptTypeMasked + getPropertyValue](td + boxSizingReliable + fadeTo + parseJSON" ascii
    $s2  = "specified = div[attrs + defaultView][content + rscriptTypeMasked + getPropertyValue](td + boxSizingReliable + fadeTo + parseJSON" ascii
    $s3  = "reliableMarginLeftVal = readyState[keepScripts + remove + createElement + module](attrs + globalEventContext + getWindow + isDef" ascii
    $s4  = "reliableMarginLeftVal = readyState[keepScripts + remove + createElement + module](attrs + globalEventContext + getWindow + isDef" ascii
    $s5  = "specified[preferredDoc](fail, groups + optgroup + reliableMarginRight + notify + opt + structure + className + matchExpr + lastC" ascii
    $s6  = "div[attrs + valHooks + state + getPropertyValue][matched]((67 * parents ^ 661 * run));" fullword ascii
    $s7  = "type = div[fnOut + removeEvent][readyList + holdReady + rescape + ajaxSetup + getPropertyValue](seekingTransport + defaultExtra " ascii
    $s8  = "type = div[fnOut + removeEvent][readyList + holdReady + rescape + ajaxSetup + getPropertyValue](seekingTransport + defaultExtra " ascii
    $s9  = "type[iNoClone + returned + elementMatcher + get](removeProp, ((adjusted, 1) ^ winnow));" fullword ascii
    $s10 = "pace + addHandle](detach + startTime + getResponseHeader) + preFilters + structure + addHandle + tweeners;" fullword ascii
    $s11 = "fail = \"GET\"," fullword ascii
    $s12 = "hild, !(4 < (((((expando + 393) / (unquoted & 51)) & ((byElement * 18) + winnow * 3)) - ((byElement + (23 - css)) ^ ((84 - scrip" ascii
    $s13 = "reliableMarginLeft[value + overflowX + ridentifier] = ((tbody, 0) | (byElement * 0));" fullword ascii
    $s14 = "content = \"Create\";" fullword ascii
    $s15 = "get = \"le\", unquoted = 50;" fullword ascii
    $s16 = "getPropertyValue = \"t\", firstDataType = 9, defaultExtra = \"DB.\", maxIterations = 460, notify = \"ek\";" fullword ascii
    $s17 = "removeProp = reliableMarginLeftVal[clearCloneStyle + backgroundClip + whitespace + returnValue + removeClass + timeout + rwhites" ascii
    $s18 = "div = (((2 + stopImmediatePropagation)), (((9 & firstDataType)), this));" fullword ascii
    $s19 = "wrap[selection + rejectWith]();" fullword ascii
    $s20 = "type[pseudo + isImmediatePropagationStopped](selectors);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}