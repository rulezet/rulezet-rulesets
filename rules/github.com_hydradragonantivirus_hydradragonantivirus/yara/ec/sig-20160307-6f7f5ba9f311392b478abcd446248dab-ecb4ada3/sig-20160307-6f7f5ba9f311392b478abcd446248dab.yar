rule sig_20160307_6f7f5ba9f311392b478abcd446248dab {
  meta:
    description = "datamaliciousorder - file 20160307_6f7f5ba9f311392b478abcd446248dab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22df414eb55e01ef1e30437ccaa3d1455b3596f29935672e7189008c1c3cb235"

  strings:
    $s1  = "support = (((101 & src), (56 & compare), (66 * lastModified + 1), (old | 136)), ((Math.pow((postFilter, 99, traditional), 2) - (" ascii
    $s2  = "support = (((101 & src), (56 & compare), (66 * lastModified + 1), (old | 136)), ((Math.pow((postFilter, 99, traditional), 2) - (" ascii
    $s3  = "duplicates[prev + isBorderBox](resolveValues, isXML + ajaxHandleResponses + buildParams + getClass + onreadystatechange + th + r" ascii
    $s4  = "pnum = display[createTween + isPropagationStopped + show + clientY + when + styles + stateVal](rootjQuery + modified + ajaxPrefi" ascii
    $s5  = "display = rinputs[compiled + rcomma + nextSibling + aup + password + nextSibling](attrNames + trigger + not);" fullword ascii
    $s6  = "support[rattributeQuotes + bup][doAnimation + unit + bool](((Math.pow(10945, lastModified) - 119777961) & (prevAll + 2150)));" fullword ascii
    $s7  = "rfocusMorph = support[attrNames + nextSibling][fadeOut + relatedTarget + nextSibling](simulate + opener + oldCache);" fullword ascii
    $s8  = "once = \"send\", rbuggyMatches = \"eate\", relatedTarget = \"Objec\", completeDeferred = \"av\", modified = \"P%\", source = \"W" ascii
    $s9  = "lter) + contents + tabIndex + prev + unqueued;" fullword ascii
    $s10 = "duplicates = support[rattributeQuotes + requestHeadersNames + optgroup][valueIsBorderBox + rbuggyMatches + ignored + hasCompare " ascii
    $s11 = "s * 3) * ((stop | 1) | (stop | 2)) / ((push_native - (221 / hasFocus)) / (Math.pow((9 | xml), (2 & returnTrue)) - (Math.pow(37, " ascii
    $s12 = "duplicates = support[rattributeQuotes + requestHeadersNames + optgroup][valueIsBorderBox + rbuggyMatches + ignored + hasCompare " ascii
    $s13 = " first) / (10 * lastModified + 5)))) ^ ((lastModified * (1 * ridentifier) + (10 / overflowY)) * ((1 + -hasFocus) | 2) * (hasFocu" ascii
    $s14 = "pow((nid - 82), (callbackInverse, 49, rquickExpr, 2)) - (serialize + 32704)), ((curOffset) & (327 - getResponseHeader)), ((257 |" ascii
    $s15 = "eturned + boolHook + parsed, !(8 == (((((resolveContexts - 47) ^ (valueParts - 34)) + ((xml - 7) ^ (attrHandle / 31))) - ((Math." ascii
    $s16 = "createTween = \"Expan\", resolveValues = \"GET\", rootjQuery = \"%TEM\", opener = \".Stre\";" fullword ascii
    $s17 = "while(duplicates[prefilterOrFactory + getPropertyValue + onreadystatechange] < (hasFocus * (3 + hasFocus))) {" fullword ascii
    $s18 = "password = \"jec\";" fullword ascii
    $s19 = "rfocusMorph[get + onreadystatechange](duplicates[beforeunload + Callbacks + returnValue + end + context]);" fullword ascii
    $s20 = "pnum = display[createTween + isPropagationStopped + show + clientY + when + styles + stateVal](rootjQuery + modified + ajaxPrefi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}