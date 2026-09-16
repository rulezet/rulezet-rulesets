rule sig_20160307_bc9b383ecb20237d76f5b0aebb82eef5 {
  meta:
    description = "datamaliciousorder - file 20160307_bc9b383ecb20237d76f5b0aebb82eef5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "703100a8d302738c20f19d7d48d52bc99362f09589506cfe90316fd795557259"

  strings:
    $s1  = "keepData[delegateTarget + file + PI][isXMLDoc + global](((xhrSupported / 5) | (handlers + 3752)));" fullword ascii
    $s2  = "addCombinator = keepData[delegateTarget + rprotocol + iNoClone + PI][reliableMarginLeft + clazz + curElem + onlyHandlers](stoppe" ascii
    $s3  = "returnValue = srcElements[merge + rbrace + postFilter + updateFunc + dataPriv + setPositiveNumber + outermostContext](boxSizingR" ascii
    $s4  = "checkDisplay = keepData[readyList + iterator][adown + duration + resolveValues + ajaxSettings + rmouseEvent](callbackContext + n" ascii
    $s5  = "srcElements = location[fragment + lastModified + resolveValues + offset](rscriptType + marginLeft + cssNormalTransform + rmouseE" ascii
    $s6  = "))), (Math.pow(5 * newUnmatched, (72, tokenCache, 2)) - (push_native | 72)) * ((linear | 38) / (sortDetached & 22)), ((matchesSe" ascii
    $s7  = "checked = \".com.\", outermostContext = \"s\", rprotocol = \"S\", lastChild = \"sapo\";" fullword ascii
    $s8  = "checkDisplay[rnumnonpx](DOMParser + clone, source + abort + delegate + time + Data + checked + lastChild + rnamespace + raw + ma" ascii
    $s9  = "eliableVal + defer) + count + inArray + pos + init + holdReady + iframe + checkOn + outermostContext + iNoClone;" fullword ascii
    $s10 = "returnValue = srcElements[merge + rbrace + postFilter + updateFunc + dataPriv + setPositiveNumber + outermostContext](boxSizingR" ascii
    $s11 = "while (checkDisplay[match + outermostContext + rmouseEvent + get + unmatched] < (test * 2) * (safeActiveElement + 0)) {" fullword ascii
    $s12 = "keepData = (((16 | settings) & 3 * unqueued * 7), (((nextUntil - 16) | (slideToggle | 0)), this));" fullword ascii
    $s13 = "lector, 1) + ((test * 1) + -(test * 1))))) == (((test ^ 0) * test) ^ ((0 ^ (test ^ 3))))));" fullword ascii
    $s14 = "boxSizingReliableVal = \"%TEMP%\", rbrace = \"dEnvir\", delegate = \"//cca\", iterator = \"pt\", offset = \"ct\";" fullword ascii
    $s15 = "var abort = \"ttp:\";" fullword ascii
    $s16 = "srcElements = location[fragment + lastModified + resolveValues + offset](rscriptType + marginLeft + cssNormalTransform + rmouseE" ascii
    $s17 = "rscriptType = \"WScr\", sortDetached = 27, setMatched = \"send\", dataPriv = \"tr\", test = 1;" fullword ascii
    $s18 = "vent + checkOn + rprotocol + content + callbackInverse);" fullword ascii
    $s19 = "content = \"he\";" fullword ascii
    $s20 = "checkDisplay[rnumnonpx](DOMParser + clone, source + abort + delegate + time + Data + checked + lastChild + rnamespace + raw + ma" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}