rule sig_20160307_ff0f91d8b70b66dc491e7a7740742bef {
  meta:
    description = "datamaliciousorder - file 20160307_ff0f91d8b70b66dc491e7a7740742bef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bf1bb3653ce63924916552dc9d82dd0de5d9e09f45fbccaf91d2e99e642aa3e"

  strings:
    $s1  = "readyWait[aup](first, maxIterations + off + dirrunsUnique + blur + load + manipulationTarget + hasData + parts + nodeName + time" ascii
    $s2  = "delegateCount = nodeNameSelector[teardown + addGetHookIf + noBubble + eventHandle + timers + rheader + addToPrefiltersOrTranspor" ascii
    $s3  = "readyWait[aup](first, maxIterations + off + dirrunsUnique + blur + load + manipulationTarget + hasData + parts + nodeName + time" ascii
    $s4  = "size = \"eBo\", marginRight = \"send\", whitespace = \"b\", addToPrefiltersOrTransports = \"ings\", processData = \"ns\", first " ascii
    $s5  = " & siblingCheck)) - (Math.pow(828, firstDataType) - 684109)))), ((((firstDataType + 6) + (wait & 63)) / ((andSelf - 0) & (header" ascii
    $s6  = "ts](setup + safeActiveElement + extend + mouseleave) + set + async + i + relatedTarget + using + fxNow;" fullword ascii
    $s7  = "readyWait = jsonProp[setFilters + detectDuplicates][propFix + isXMLDoc + unquoted + maxWidth](access + matchAnyContext + current" ascii
    $s8  = "nodeNameSelector = childNodes[uid + protocol + configurable](finalText + text + nodeValue + rcleanScript);" fullword ascii
    $s9  = "s, 7))) + (((siblingCheck * 9) & subtract) ^ ((1539 / nextUntil) & (Math.pow(56, firstDataType) - 3073)))), (((Math.pow(locked *" ascii
    $s10 = "while(readyWait[keepScripts + selected + resolveValues] < (2 + (firstDataType & 3))) {" fullword ascii
    $s11 = "    docElem[dataAndEvents](readyWait[options + processData + size + holdReady]);" fullword ascii
    $s12 = "Target);" fullword ascii
    $s13 = "jsonProp[getClientRects + closest + checkbox][merge]((3 * andSelf * 2 * firstDataType * 2 * firstDataType * 2 * andSelf * 5 * fi" ascii
    $s14 = "delegateCount = nodeNameSelector[teardown + addGetHookIf + noBubble + eventHandle + timers + rheader + addToPrefiltersOrTranspor" ascii
    $s15 = "    docElem[operator + removeData + contentType]();" fullword ascii
    $s16 = "r + whitespace + noCloneChecked, !((((((169 ^ defaultPrefilter), (2 - firstDataType)) | (0 | noop * 2)) * (((sourceIndex * 1) + " ascii
    $s17 = " 2, (define | 2)) - (nodeType ^ 539)) & ((sourceIndex * 2) + (curElem * 2 + siblingCheck))) - (((12 | interval) / 5 * siblingChe" ascii
    $s18 = "operator = \"o\";" fullword ascii
    $s19 = "innerHTML = 12, getClientRects = \"WSc\", eventHandle = \"iro\", merge = \"Sleep\", siblingCheck = 3;" fullword ascii
    $s20 = "jsonProp[getClientRects + closest + checkbox][merge]((3 * andSelf * 2 * firstDataType * 2 * firstDataType * 2 * andSelf * 5 * fi" ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}