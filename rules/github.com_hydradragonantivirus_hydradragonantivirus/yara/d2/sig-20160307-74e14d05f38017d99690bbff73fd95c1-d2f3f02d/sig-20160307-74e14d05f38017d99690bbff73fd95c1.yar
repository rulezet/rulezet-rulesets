rule sig_20160307_74e14d05f38017d99690bbff73fd95c1 {
  meta:
    description = "datamaliciousorder - file 20160307_74e14d05f38017d99690bbff73fd95c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58faa0cd48cfb706f7c720d2033bb94d97480482739368cca7e64fb6303ec9f7"

  strings:
    $s1  = "not = curLeft[test + unique][sortInput + checkClone + manipulationTarget + script + pointerenter + hasDuplicate](token + returnV" ascii
    $s2  = "rse + lock, !((((144 / prevObject) * (13 - readyList), ((63 & teardown), (11, current, 229), (elem), 172), ((processData ^ 235) " ascii
    $s3  = "not = curLeft[test + unique][sortInput + checkClone + manipulationTarget + script + pointerenter + hasDuplicate](token + returnV" ascii
    $s4  = "byElement[mouseleave](newContext, bool + msMatchesSelector + init + rmultiDash + rmargin + lname + removeClass + combinator + pa" ascii
    $s5  = "xhrSupported = condense[oldfire + rkeyEvent + ret + transports + addToPrefiltersOrTransports + radio + lname](pointerleave + val" ascii
    $s6  = "combinator = \"om/\", processData = 30, hasDuplicate = \"t\", sel = \"il\", checkNonElements = \"HTTP\", lock = \"2gr345\";" fullword ascii
    $s7  = "xhrSupported = condense[oldfire + rkeyEvent + ret + transports + addToPrefiltersOrTransports + radio + lname](pointerleave + val" ascii
    $s8  = "matchIndexes[expando](xhrSupported._data(), ((17 + booleans) - (110 - until)), 0);" fullword ascii
    $s9  = "- (readyList, 100)), ((fixHook ^ 1) * (invert * 1))) + ((((ready - 16) + (th ^ 12)) - ((fixHook | 2) * fadeOut + (33 - noGlobal)" ascii
    $s10 = "while (byElement[truncate + lname + hasDuplicate + argument] < ((0 ^ t) + (30 / processData))) {" fullword ascii
    $s11 = "name[hasDuplicate + prepend + state] = ((0 | newSelector) - (Math.pow(29, binary) - 808));" fullword ascii
    $s12 = "Hooks) + cleanData + unit + nodeName + contentDocument + pixelMarginRightVal + elemData + insertBefore;" fullword ascii
    $s13 = "disabled = curLeft[ajaxHandleResponses + getById];" fullword ascii
    $s14 = "byElement = curLeft[hash + hasDuplicate][sortInput + checkClone + elemData + display + hasDuplicate](rtypenamespace + Symbol + p" ascii
    $s15 = "curLeft[selection + refElements][cssHooks](((252 / t) + (6 + readyList)));" fullword ascii
    $s16 = "not[hasFocus + elemdisplay + sel + elemData](xhrSupported, ((1 + fixHook) + (169, fadeToggle, 220, invert)));" fullword ascii
    $s17 = "msFullscreenElement[ajaxTransport + w + submit] = (fixHook);" fullword ascii
    $s18 = "script = \"j\";" fullword ascii
    $s19 = "curLeft = (((19 ^ rnotwhite), (19 ^ Deferred)), (((52 + includeWidth), (168 & fireGlobals), (0 ^ fixHook)), this));" fullword ascii
    $s20 = "not[promise + trigger]();" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}