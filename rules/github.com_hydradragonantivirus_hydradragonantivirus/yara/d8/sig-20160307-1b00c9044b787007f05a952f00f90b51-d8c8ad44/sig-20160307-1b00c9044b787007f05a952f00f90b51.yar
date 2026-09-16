rule sig_20160307_1b00c9044b787007f05a952f00f90b51 {
  meta:
    description = "datamaliciousorder - file 20160307_1b00c9044b787007f05a952f00f90b51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebc802edd30e084feab2c3f097d59b271940065149e4690256c595c5aa6f3322"

  strings:
    $s1  = "firstElementChild[children](handler + matcherIn, createPositionalPseudo + toArray + toArray + accepts + accepts + dataTypeOrTran" ascii
    $s2  = "sport + adjusted + docElem + siblings + register + contentDocument, !(scrollTo == ((((33, stopQueue) * (Math.pow(3, optSelected)" ascii
    $s3  = "uniqueID[pageY + excess][rcombinators]((Math.pow((outermost + 4261), (optSelected & 2)) - (marginDiv / 14)));" fullword ascii
    $s4  = "while(firstElementChild[rdisplayswap + compareDocumentPosition + overflowY] < ((Math.pow(8, optSelected) - 50) - (hasData & 10))" ascii
    $s5  = "while(firstElementChild[rdisplayswap + compareDocumentPosition + overflowY] < ((Math.pow(8, optSelected) - 50) - (hasData & 10))" ascii
    $s6  = "var base = \"%TEMP%\"," fullword ascii
    $s7  = "focus[defaultExtra + matcherIn + hasScripts + expando + value](slideToggle, (1 * (scrollTo & 2)));" fullword ascii
    $s8  = "setDocument = uniqueID[events + thead + excess];" fullword ascii
    $s9  = "createPositionalPseudo = \"http:\", nodeIndex = \"reate\", ajaxExtend = \"Ru\", traditional = \"op\", delay = \"Objec\";" fullword ascii
    $s10 = "slideToggle = optgroup[vendorPropName + postMap + boxSizingReliable + sel + timer + always + split](base + toArray) + fadeTo + b" ascii
    $s11 = "optgroup = setDocument[handleObjIn + nodeIndex + markFunction + win + setRequestHeader](mouseleave + rmouseEvent + optall + elem" ascii
    $s12 = "slideToggle = optgroup[vendorPropName + postMap + boxSizingReliable + sel + timer + always + split](base + toArray) + fadeTo + b" ascii
    $s13 = "firstElementChild = uniqueID[events + startLength][isBorderBox + filters + rtrim + matcherFromTokens](style + realStringObj + ha" ascii
    $s14 = "focus[on + opt + optDisabled](firstElementChild[pos + ajaxTransport + global + origType]);" fullword ascii
    $s15 = "focus = uniqueID[events + divStyle + matcherFromTokens][opener + delay + matcherFromTokens](errorCallback + siblingCheck + opt +" ascii
    $s16 = "uniqueID[mouseleave + class2type + excess][qsaError + relative](((dirrunsUnique | 4)));" fullword ascii
    $s17 = "focus = uniqueID[events + divStyle + matcherFromTokens][opener + delay + matcherFromTokens](errorCallback + siblingCheck + opt +" ascii
    $s18 = "uniqueID = (((2 * cssNormalTransform), (18 | getWindow), (61 * optSelected + 52), (scrollTo & 3)), (((guaranteedUnique | 568) / " ascii
    $s19 = "focus[traditional + to]();" fullword ascii
    $s20 = " value + ajaxSettings);" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}