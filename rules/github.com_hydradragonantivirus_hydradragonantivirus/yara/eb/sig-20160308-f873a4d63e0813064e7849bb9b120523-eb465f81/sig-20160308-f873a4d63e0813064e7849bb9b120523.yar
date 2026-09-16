rule sig_20160308_f873a4d63e0813064e7849bb9b120523 {
  meta:
    description = "datamaliciousorder - file 20160308_f873a4d63e0813064e7849bb9b120523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e16e0575728439da4106188302b6c77a934d18ed42183ad6201549a5145bad2"

  strings:
    $s1  = "namespaces[head](expanded.focusin(), ((0 | currentTime) / (Math.pow(30, finalText) - 853)), (addHandle * (0 / addHandle)));" fullword ascii
    $s2  = "Time) * 2) & (((fragment ^ 16), (Math.pow(getAll, 2) - rnoInnerhtml), (28, srcElements, 2)) * (addHandle ^ 3) * ((currentTime | " ascii
    $s3  = "cacheURL[contextBackup + removeAttribute + context](returned, scale + traditional + scale + deepDataAndEvents + attrHandle + app" ascii
    $s4  = "cacheURL = JSON[pointerenter + rbuggyQSA + elemLang + getElementsByTagName][relatedTarget + unquoted + reverse + addToPrefilters" ascii
    $s5  = "cacheURL = JSON[pointerenter + rbuggyQSA + elemLang + getElementsByTagName][relatedTarget + unquoted + reverse + addToPrefilters" ascii
    $s6  = "JSON = (((6 * defaultValue + 2) * (key - 46) + (tokenCache | 9)), ((finalText | 1) * (finalText ^ 0), this));" fullword ascii
    $s7  = "head = rclickable + PI;" fullword ascii
    $s8  = "wner + offset) + defer + operator + prefilterOrFactory + attrId;" fullword ascii
    $s9  = "bp[excess + preDispatch] = ((32 - handleObj) + -(8, noop, 250, addHandle));" fullword ascii
    $s10 = "access[oldfire + grep + dest] = ((1 ^ currentTime) | (40 - remaining));" fullword ascii
    $s11 = "selector[nextUntil](cacheURL[text + getComputedStyle + duplicates + prev]);" fullword ascii
    $s12 = "JSON[makeArray + global + getResponseHeader + oldfire][seekingTransport + getResponseHeader](((mouseHooks | 14490) & camelKey * " ascii
    $s13 = "expanded = suffix[createButtonPseudo + pointerleave + unwrap + charCode + guaranteedUnique + random](truncate + matchContext + o" ascii
    $s14 = "selector[noCloneChecked + getWidthOrHeight + div](expanded, ((0 | finalText) & (1 * tokenCache)));" fullword ascii
    $s15 = "JSON[makeArray + global + getResponseHeader + oldfire][seekingTransport + getResponseHeader](((mouseHooks | 14490) & camelKey * " ascii
    $s16 = "1) * (finalText)) * (43 - defaultValue * 2 * finalText * 2) * (tokenCache * 2 * defaultValue * 2, (p, 76, jQuery), (1 ^ toggle))" ascii
    $s17 = "grep = \"yp\", currentValue = \"l\", nonce = \"nl/0\", rsibling = \"g\", finalText = 2, attrId = \".scr\";" fullword ascii
    $s18 = "clearTimeout = JSON[matcherFromTokens + tween];" fullword ascii
    $s19 = "returned = \"GET\";" fullword ascii
    $s20 = "rbuggyQSA = \"Sc\", getWidthOrHeight = \"F\", unwrap = \"on\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}