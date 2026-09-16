rule sig_20160307_9a8ed415134c87119eb481c87b8ae975 {
  meta:
    description = "datamaliciousorder - file 20160307_9a8ed415134c87119eb481c87b8ae975.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ef024a2963741ad4169dcd605fc5154a7bcdfdd2a6f902b986ecadd62b984a6"

  strings:
    $s1  = "getter = inPage[includeWidth + dataAttr][split + documentElement + outermostContext](globalEval + fontWeight + locked + XMLHttpR" ascii
    $s2  = "while(setDocument[clone + checkNonElements + optDisabled + createInputPseudo] < (Math.pow((cached / 18), (thead, 182, matched, 2" ascii
    $s3  = "getter[rcomma + undelegate + sibling]();" fullword ascii
    $s4  = "getter = inPage[includeWidth + dataAttr][split + documentElement + outermostContext](globalEval + fontWeight + locked + XMLHttpR" ascii
    $s5  = "setDocument[slideToggle](serializeArray, uniqueID + funcName + getAttribute + origFn + rxhtmlTag + event + callbackName + docEle" ascii
    $s6  = "inPage[conditionFn + rscriptTypeMasked][opts]((returnValue * 3) * percent * (125, percent) * (110 / isDefaultPrevented) * 2 * (d" ascii
    $s7  = "inPage[conditionFn + rscriptTypeMasked][opts]((returnValue * 3) * percent * (125, percent) * (110 / isDefaultPrevented) * 2 * (d" ascii
    $s8  = "getter[rnative + responseHeaders](setDocument[click + emptyGet + htmlPrefilter + appendTo + checkNonElements]);" fullword ascii
    $s9  = "getter[maxWidth + ajaxExtend + b](visible, ((returnValue ^ 0) ^ addGetHookIf));" fullword ascii
    $s10 = "getter[removeAttr + preventDefault]();" fullword ascii
    $s11 = "while(setDocument[clone + checkNonElements + optDisabled + createInputPseudo] < (Math.pow((cached / 18), (thead, 182, matched, 2" ascii
    $s12 = "removeData = \"ue\", chainable = \"cr\", clone = \"read\", getAttribute = \"//ww\";" fullword ascii
    $s13 = "visible = _data[addCombinator + msg + firing + rmsPrefix + resolveContexts + hasContent + realStringObj + classes + optDisabled]" ascii
    $s14 = "visible = _data[addCombinator + msg + firing + rmsPrefix + resolveContexts + hasContent + realStringObj + classes + optDisabled]" ascii
    $s15 = "_data = traditional[el + defaultDisplay + transport + xhrFields + outermostContext](id + slideUp + chainable + currentValue + rb" ascii
    $s16 = "_data = traditional[el + defaultDisplay + transport + xhrFields + outermostContext](id + slideUp + chainable + currentValue + rb" ascii
    $s17 = "inPage = (((4 * nodeType + 3) * (delegateCount ^ 2)), (((Math.pow(diff, 2) - oldCallbacks) - (Math.pow(34, rCRLF) - 1113)), this" ascii
    $s18 = "(((structure ^ 50), (delegateCount ^ 0)) / (Math.pow((returnValue * 3), rCRLF) - (0 | percent)))) | ((((130 ^ boxSizingReliable)" ascii
    $s19 = "inPage = (((4 * nodeType + 3) * (delegateCount ^ 2)), (((Math.pow(diff, 2) - oldCallbacks) - (Math.pow(34, rCRLF) - 1113)), this" ascii
    $s20 = "elemData[transport + src] = ((returnValue / 1) + (delegateCount / 4));" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}