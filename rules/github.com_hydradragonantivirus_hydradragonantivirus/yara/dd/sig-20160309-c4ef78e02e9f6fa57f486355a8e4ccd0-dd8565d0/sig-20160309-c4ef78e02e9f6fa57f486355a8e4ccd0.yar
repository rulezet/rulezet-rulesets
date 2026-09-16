rule sig_20160309_c4ef78e02e9f6fa57f486355a8e4ccd0 {
  meta:
    description = "datamaliciousorder - file 20160309_c4ef78e02e9f6fa57f486355a8e4ccd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3212bfea91ec5194a278ac74ccb4eeb84e6a9922a24b99062f67a10960e3c6"

  strings:
    $s1  = "resolveValues[root](fnOver, bup + ret + rwhitespace + emptyGet + styles + makeArray + random + siblingCheck + returnFalse + msg," ascii
    $s2  = "resolveValues[root](fnOver, bup + ret + rwhitespace + emptyGet + styles + makeArray + random + siblingCheck + returnFalse + msg," ascii
    $s3  = " !(((((1 * dataAndEvents) * (1 * dataAndEvents)) * ((Math.pow(2 * xhrFields * 2 * xhrFields * 2, (xhrFields | 0)) - (next, 191, " ascii
    $s4  = "optionSet = setGlobalEval[map + duplicates + preDispatch][setPositiveNumber + structure + callbackName](rkeyEvent + handleObj + " ascii
    $s5  = "optionSet = setGlobalEval[map + duplicates + preDispatch][setPositiveNumber + structure + callbackName](rkeyEvent + handleObj + " ascii
    $s6  = "defaultValue)) - (5 * stopQueue - (95 - propName)))) * ((((1092 / what) & (103, jsonProp, 22, radioValue)) - ((67 + what) - (10 " ascii
    $s7  = "setGlobalEval = ((2 * xhrFields * 2 * xhrFields * 3 * xhrFields | 2 * xhrFields * 2 * xhrFields * 2 * xhrFields), ((3 & rmargin)" ascii
    $s8  = "var random = \"m/log\"," fullword ascii
    $s9  = "optionSet[resolveWith + isHidden + init + close + chainable + init](cleanData, ((175, isDefaultPrevented, 248, rmargin) & (2 ^ p" ascii
    $s10 = "stopped[stateString + init]();" fullword ascii
    $s11 = "gotoEnd = setGlobalEval[mouseleave + preDispatch];" fullword ascii
    $s12 = "optionSet[resolveWith + isHidden + init + close + chainable + init](cleanData, ((175, isDefaultPrevented, 248, rmargin) & (2 ^ p" ascii
    $s13 = "td = resolveValues[file + values + handlerQueue + mappedTypes];" fullword ascii
    $s14 = "setGlobalEval[propFilter + apply + parseOnly][width + amd](((940 * l + 856) | xhrFields * 2 * matchExpr * 11 * xhrFields * 2));" fullword ascii
    $s15 = " * (1 * xhrFields) * (1 * rmargin), this));" fullword ascii
    $s16 = "cleanData = cssNormalTransform[implicitRelative + elemdisplay + propHooks + toggleClass + fadeTo + offsetWidth](rhtml + speed) +" ascii
    $s17 = "triggered = \"Run\";" fullword ascii
    $s18 = "root = \"open\";" fullword ascii
    $s19 = "cssNormalTransform = gotoEnd[tmp + init + empty + callbackName](teardown + unqueued + init + lname);" fullword ascii
    $s20 = "stopped = optionSet;" fullword ascii

  condition:
    uint16(0) == 0x6977 and
    8 of them
}