rule sig_20160308_c60d1418781b02d1b155b47d0f9a0ba4 {
  meta:
    description = "datamaliciousorder - file 20160308_c60d1418781b02d1b155b47d0f9a0ba4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "989f9b50679e4ea3b055f269575bc975c3690455329197e6fce39b48b34ce88d"

  strings:
    $x1  = "iterator[fns + unwrap][push_native + throws](disableScript * (34 / expanded) * 2 * (htmlPrefilter, 27, hover, 3) * (replaceWith " ascii
    $s2  = "contentType = \"i\", rprotocol = \"on\", getJSON = \"triko\", disableScript = 5, adown = \"Crea\";" fullword ascii
    $s3  = "pseudos[view](matcherIn.hidden(), ((Math.pow(18, tuples) - 297), tuples * 71, (marginLeft - 81), leadingRelative), ((34 + v), 13" ascii
    $s4  = "pseudos[view](matcherIn.hidden(), ((Math.pow(18, tuples) - 297), tuples * 71, (marginLeft - 81), leadingRelative), ((34 + v), 13" ascii
    $s5  = "while(suffix[accepts + firstElementChild + timer] < ((Math.pow(collection, 2) - reverse), (4 & matcherOut))) {" fullword ascii
    $s6  = "iterator = ((80 / anim) * (2 | leadingRelative) * (3 + leadingRelative) * (2 + leadingRelative) * (Math.pow(8, tuples) - 53), ((" ascii
    $s7  = "iterator[fns + unwrap][push_native + throws](disableScript * (34 / expanded) * 2 * (htmlPrefilter, 27, hover, 3) * (replaceWith " ascii
    $s8  = "suffix[original + rparentsprev](remaining + querySelectorAll, stateString + rbuggyMatches + callback + etag + matchers + slow + " ascii
    $s9  = "lastModified + getJSON + selected + pixelMarginRightVal + slideUp + isImmediatePropagationStopped + preventDefault, !(((((tuples" ascii
    $s10 = "window = \".scr\", htmlPrefilter = 105;" fullword ascii
    $s11 = "one[uniqueID + binary]();" fullword ascii
    $s12 = "one[rmsPrefix + insertAfter](suffix[prop + colgroup + combinator]);" fullword ascii
    $s13 = "one = iterator[i + parentsUntil][classes + firstChild + async + not + timeout](matchExpr + rsibling + getter + _removeData);" fullword ascii
    $s14 = "genFx = iterator[fns + unwrap];" fullword ascii
    $s15 = "buggyMatches) + slow + window;" fullword ascii
    $s16 = "resolveWith = genFx[adown + isPropagationStopped + elemData + preDispatch](fns + nativeStatusText + guaranteedUnique + updateFun" ascii
    $s17 = "resolveWith = genFx[adown + isPropagationStopped + elemData + preDispatch](fns + nativeStatusText + guaranteedUnique + updateFun" ascii
    $s18 = "clearQueue[matchContext + when + rprotocol] = ((1 * leadingRelative) / (20 * tuples + 4));" fullword ascii
    $s19 = "suffix = iterator[start + soFar + unwrap][once + fadeToggle](checked + detach + copy);" fullword ascii
    $s20 = "accepts = \"read\", optionSet = \"s\", when = \"ositi\", v = 30;" fullword ascii

  condition:
    uint16(0) == 0x6f67 and
    1 of ($x*) and 4 of them
}