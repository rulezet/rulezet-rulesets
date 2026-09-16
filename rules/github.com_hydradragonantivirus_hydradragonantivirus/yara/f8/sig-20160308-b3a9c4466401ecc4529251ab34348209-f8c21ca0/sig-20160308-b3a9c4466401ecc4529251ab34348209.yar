rule sig_20160308_b3a9c4466401ecc4529251ab34348209 {
  meta:
    description = "datamaliciousorder - file 20160308_b3a9c4466401ecc4529251ab34348209.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8210ca6adb05b7dbe184434fc2613a0e37e80e6430360f50b7cd540c5b39fb4c"

  strings:
    $x1  = "parseHTML[escapedWhitespace + soFar](method + htmlPrefilter, isBorderBox + fn + caption + cloneCopyEvent + defer + keyHooks + ma" ascii
    $s2  = "tchAnyContext + getComputedStyle + elemLang, !(((Math.pow((((combinator & 1) * (tweener | 25)) & (Math.pow((mouseHooks - 63), (c" ascii
    $s3  = "teType & 1023))) / (Math.pow(((bind | 64) - (init ^ 51)), ((rfocusable * 10 + clazz) - (17 * clazz + 16))) - ((forward - 24) | (" ascii
    $s4  = "eventDoc[maxIterations + pipe + optDisabled](readyList, (38 - t));" fullword ascii
    $s5  = "Math.pow(timerId, 2) - value), (0 | rneedsContext)) * (3, firstElementChild, 3) + (((documentIsHTML / 1) * (bySet - 24) + (combi" ascii
    $s6  = "dataShow = 13, pipe = \"aveToF\", eased = \"write\", currentTarget = \"Cre\";" fullword ascii
    $s7  = "needsContext) & ((0 ^ combinator) * (16 - guaranteedUnique))) * ((2 * clazz * 11 * clazz * 2 | (forward & 27)) - ((dataShow + 12" ascii
    $s8  = "setRequestHeader) ^ (41 + getResponseHeader)), (2 ^ (bind ^ 0))) - (rneedsContext * 2 * expand * 2 - (m * 57 + size)))), ((3 & r" ascii
    $s9  = "split = ((Math.pow((98, contextBackup), (1 + combinator)) - (22451 & animated)), ((Math.pow((4 ^ nextSibling), 2) - (reliableMar" ascii
    $s10 = " / resolveWith)) ^ ((7 ^ resolveWith) + 0)), (((Math.pow((teardown & 111), (clazz ^ 0)) - (createPseudo, 145, stop)), ((45 ^ com" ascii
    $s11 = "ombinator ^ 3)) - (rsubmittable ^ 194))), (((bind / 23) & (combinator * 1)) | ((clazz | 2) & rneedsContext))) - (Math.pow(((8 | " ascii
    $s12 = "rty & 11)))), ((bind | 1) ^ ((p - 30) ^ (bind / 50))) * (((combinator ^ 8) * (Math.pow(rfocusable, 2) - firstElementChild) + (12" ascii
    $s13 = "split = ((Math.pow((98, contextBackup), (1 + combinator)) - (22451 & animated)), ((Math.pow((4 ^ nextSibling), 2) - (reliableMar" ascii
    $s14 = "removeEventListener = \".\", cloneCopyEvent = \"p.u\", mouseHooks = 78, setRequestHeader = 196, forward = 24;" fullword ascii
    $s15 = "eventDoc = split[sibling + elements][currentTarget + iframe + cssNumber + elements](setup + slideUp + apply + cached + parseXML)" ascii
    $s16 = "split[postMap + deep][replaceWith + end + elementMatchers](((16642 | inPage) - (1065 + rbuggyMatches)));" fullword ascii
    $s17 = "eventDoc = split[sibling + elements][currentTarget + iframe + cssNumber + elements](setup + slideUp + apply + cached + parseXML)" ascii
    $s18 = "hookFn[completed](readyList.username(), (1 & (bind ^ 0)), ((protocol | 64), (time & 255), clazz * 79, (combinator * 0)));" fullword ascii
    $s19 = " 0)) | ((j - 107) / (siblingCheck & 19))) | (((identifier - 1346) & (propFix, 172, pseudo, 2455)) / ((tbody - 18) * (definePrope" ascii
    $s20 = "hasFocus + 276)))), ((((responseText & 249) - cssText) ^ ((0 | ret) | (0 | proxy))) / (((5 * firstElementChild + 2) - (dataShow " ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}