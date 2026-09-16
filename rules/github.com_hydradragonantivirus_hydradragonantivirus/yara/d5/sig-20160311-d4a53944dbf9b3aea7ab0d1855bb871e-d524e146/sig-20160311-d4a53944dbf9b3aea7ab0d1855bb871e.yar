rule sig_20160311_d4a53944dbf9b3aea7ab0d1855bb871e {
  meta:
    description = "datamaliciousorder - file 20160311_d4a53944dbf9b3aea7ab0d1855bb871e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f70a5cc904128b69c13b2c6cda4c99ae0e79ff0cab5e46ea7701f2ede5b553c3"

  strings:
    $x1  = "show[unqueued + \"e\" + pixelMarginRight](\"G\" + pseudos, \"http\".requestHeadersNames() + timerId + \"lit\" + max + \"w.co.i\"" ascii
    $s2  = "append = deepDataAndEvents[\"Expan\" + type + \"ronmen\".requestHeadersNames() + rheaders + \"ing\" + compiled](\"%TEMP%\" + get" ascii
    $s3  = "append = deepDataAndEvents[\"Expan\" + type + \"ronmen\".requestHeadersNames() + rheaders + \"ing\" + compiled](\"%TEMP%\" + get" ascii
    $s4  = "s + \"tguy\".requestHeadersNames() + xhrSupported, !((Math.pow(((((merge, 15) & (tuples & 15)) & ((Math.pow(rparentsprev, 2) - o" ascii
    $s5  = "* cloneNode) + (26 - index)) / (((Math.pow(19, mozMatchesSelector) - 340) - (compareDocumentPosition & 30)) * ((rfocusable + 322" ascii
    $s6  = "ctor) - 406) + toArray) * ((1 & i) * (1 * mozMatchesSelector)) + 29), (((rfxtypes, 146) - (manipulationTarget - 100)) - (reverse" ascii
    $s7  = "check = reset[nodes + \"ipt\".requestHeadersNames()][hasScripts + \"teOb\" + prependTo](\"ADODB\" + parentsUntil + \"m\".request" ascii
    $s8  = "check = reset[nodes + \"ipt\".requestHeadersNames()][hasScripts + \"teOb\" + prependTo](\"ADODB\" + parentsUntil + \"m\".request" ascii
    $s9  = ") / (mozMatchesSelector * 15 + i))))) - (Math.pow((((7 * body + 4) * (rcssNum | 3) + (hash + 30)) / (Math.pow((cloneNode + 9), m" ascii
    $s10 = "reset = ((3 + mozMatchesSelector) * (15 / toArray) * 3, (i + (4 * toArray + 1)), eval(\"t\" + cssHooks + \"i\".requestHeadersNam" ascii
    $s11 = "show[unqueued + \"e\" + pixelMarginRight](\"G\" + pseudos, \"http\".requestHeadersNames() + timerId + \"lit\" + max + \"w.co.i\"" ascii
    $s12 = "e) & (5 * toArray))) - (1 * ((completeDeferred) | (0 | mozMatchesSelector)))), ((((11, mozMatchesSelector) + (17 - merge)) * (1 " ascii
    $s13 = "values[properties + \"u\" + pixelMarginRight](append.requestHeadersNames(((525 * xml + 410) / (firing + 3))), (uid * 2 * mozMatc" ascii
    $s14 = "ByTagName) + \"cli\".requestHeadersNames() + flag + \".s\" + rxhtmlTag + \"r\";" fullword ascii
    $s15 = "values[properties + \"u\" + pixelMarginRight](append.requestHeadersNames(((525 * xml + 410) / (firing + 3))), (uid * 2 * mozMatc" ascii
    $s16 = "deepDataAndEvents = contextBackup[\"Crea\" + expanded + \"ect\".requestHeadersNames()](DOMParser + \"t.Sh\" + sortInput);" fullword ascii
    $s17 = "reset = ((3 + mozMatchesSelector) * (15 / toArray) * 3, (i + (4 * toArray + 1)), eval(\"t\" + cssHooks + \"i\".requestHeadersNam" ascii
    $s18 = "Deferred[\"ty\" + insertAfter + \"e\".requestHeadersNames()] = ((i & 1) * (i & 1));" fullword ascii
    $s19 = "ozMatchesSelector) - (46 * toArray + 33))), (toArray * 17, (register, 68, fn, 2))) - (((url - 86) - mozMatchesSelector * 37)))) " ascii
    $s20 = "show = reset[nodes + \"ipt\".requestHeadersNames()][gotoEnd + \"eObje\" + win](\"MSXML\" + Callbacks + \"LHTTP\".requestHeadersN" ascii

  condition:
    uint16(0) == 0x6168 and
    1 of ($x*) and 4 of them
}