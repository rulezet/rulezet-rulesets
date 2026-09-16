rule sig_20160308_2901a1d060e5887907f6e1fcc6226351 {
  meta:
    description = "datamaliciousorder - file 20160308_2901a1d060e5887907f6e1fcc6226351.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b762663e4b0d29b30a6552333ede30da7760c3128ed27349741ace1e069894ec"

  strings:
    $s1  = "rcomma[l + duration][updateFunc + pageXOffset]((18, isSuccess, 145, currentTarget) * 5 * (currentTarget + 3) * (vendorPropName &" ascii
    $s2  = "delegateType[prevAll + isXML](callback, sortInput + newContext + disconnectedMatch + run + rcleanScript + curCSSTop + slideUp + " ascii
    $s3  = "global[byElement + querySelectorAll + fix](triggerHandler, ((Math.pow(16, currentTarget) - 227) - (setup - 31)));" fullword ascii
    $s4  = "namespaces + b + trim, !(currentTarget < (Math.pow((((184 ^ fromCharCode), (1421 / finish), (12 ^ boxSizingReliable), (8 - postM" ascii
    $s5  = "delegateType = rcomma[stopImmediatePropagation + merge + script][holdReady + username + lname + position](oMatchesSelector + pos" ascii
    $s6  = "ap)) | ((0 ^ getElementsByTagName) + (4 ^ getElementsByTagName))), ((3 & currentTarget))) - (((7 * fromCharCode + 3) ^ (extend *" ascii
    $s7  = "rcomma[l + duration][updateFunc + pageXOffset]((18, isSuccess, 145, currentTarget) * 5 * (currentTarget + 3) * (vendorPropName &" ascii
    $s8  = "delegateType = rcomma[stopImmediatePropagation + merge + script][holdReady + username + lname + position](oMatchesSelector + pos" ascii
    $s9  = "run = \"oko\", callback = \"GET\", sortInput = \"http:\", slideUp = \"im\", position = \"ect\";" fullword ascii
    $s10 = "triggerHandler = status[ap + token + cssHooks + rnotwhite + returnFalse + isArrayLike + writable](fxNow + invert) + siblings + P" ascii
    $s11 = "global = rcomma[camelKey + rnotwhite][timeStamp + reset + nidselect + position](createInputPseudo + getJSON + statusText + sel);" ascii
    $s12 = "while (delegateType[serializeArray + href + concat] < ((2 | currentTarget) * (1 * currentTarget))) {" fullword ascii
    $s13 = "I + winnow + getWindow;" fullword ascii
    $s14 = "markFunction[conv2](triggerHandler.cloneNode(), (getElementsByTagName + -(1 + classCache)), ((1 * classCache) & (0 / empty)));" fullword ascii
    $s15 = "rcomma = (((514 | getElementsByName) / (3 ^ elements)), (((2 ^ click) | (208, needsContext, 3)), this));" fullword ascii
    $s16 = "triggerHandler = status[ap + token + cssHooks + rnotwhite + returnFalse + isArrayLike + writable](fxNow + invert) + siblings + P" ascii
    $s17 = "global[mouseleave + fadeIn](delegateType[traditional + hasData + handle + rootjQuery]);" fullword ascii
    $s18 = "returnFalse = \"S\", rootjQuery = \"dy\", token = \"ndEnvi\", fromCharCode = 88, createInputPseudo = \"A\", traditional = \"Res" ascii
    $s19 = "script = \"pt\";" fullword ascii
    $s20 = "beforeSend[reject + then] = ((0 | classCache) | (1 * getElementsByTagName));" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}