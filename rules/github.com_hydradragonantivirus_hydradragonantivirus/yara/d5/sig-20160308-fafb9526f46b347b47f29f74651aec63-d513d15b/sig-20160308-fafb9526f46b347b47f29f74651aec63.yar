rule sig_20160308_fafb9526f46b347b47f29f74651aec63 {
  meta:
    description = "datamaliciousorder - file 20160308_fafb9526f46b347b47f29f74651aec63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56460ebecddbe5e4f2d481140f86ec2f95cb3e4feeb813d77ce17d13faa187c7"

  strings:
    $s1  = "  uniqueID[isHidden + unbind + insertAfter][globalEval + rhtml](((returnTrue & 21) + (Math.pow(buildParams, 2) - assert)));" fullword ascii
    $s2  = "uniqueID = (((144 - resolveWith) * (65 / string) + (2 + getResponseHeader)), (((53 + setRequestHeader) / (32 | fired)), this));" fullword ascii
    $s3  = "random = onload[selector + write + getElementsByTagName](support + setAttribute + namespaces + radio);" fullword ascii
    $s4  = "while (div1[off + getElementsByClassName + inspected] < ((hasCompare - 3) * (input - 48))) {" fullword ascii
    $s5  = "configurable = uniqueID[test + cloneCopyEvent][winnow + empty + second + getElementsByTagName](tokenCache + realStringObj + post" ascii
    $s6  = "one = \"%TEMP%\";" fullword ascii
    $s7  = "flag + boxSizingReliableVal + attachEvent + pageX + boxSizingReliableVal, !(((((Math.pow(26, delegateType) - 625) - (matchedCoun" ascii
    $s8  = "configurable = uniqueID[test + cloneCopyEvent][winnow + empty + second + getElementsByTagName](tokenCache + realStringObj + post" ascii
    $s9  = "uniqueID[support + status][bind + optSelected](((160, elements, 126, tabIndex) / (150 / serializeArray)));" fullword ascii
    $s10 = "configurable[n + marginDiv + matcherOut](padding, ((0 & curLeft) | (2 & delegateType)));" fullword ascii
    $s11 = "configurable[rnotwhite + inspected](div1[includeWidth + parents + adown + className + addGetHookIf + matcherIn]);" fullword ascii
    $s12 = "div1[rneedsContext](doc, pageX + selectors + step + charset + inspected + setAttribute + document + setOffset + noop + hookFn + " ascii
    $s13 = "t / 15)) - (Math.pow((delegateType * 4), delegateType) - (17 ^ hasDuplicate))) + (((9 & fired) / 9) & ((fcamelCase & 27) / (Math" ascii
    $s14 = "padding = random[rsubmittable + elemLang + what + success + Callbacks + button](one + disconnectedMatch) + nextAll + simple + to" ascii
    $s15 = "getWidthOrHeight = random;" fullword ascii
    $s16 = "+ stored + overwritten + original + event);" fullword ascii
    $s17 = "promise[preFilter + inspected] = ((98 * delegateType + 6), (curLeft * 1));" fullword ascii
    $s18 = "div1 = uniqueID[isHidden + context + elems + noCloneChecked + selectors][winnow + finalText + match + i](currentTime + isWindow " ascii
    $s19 = "types[attrHandle + firing + wrapInner] = (curCSSLeft | (0 & curLeft));" fullword ascii
    $s20 = "div1[rneedsContext](doc, pageX + selectors + step + charset + inspected + setAttribute + document + setOffset + noop + hookFn + " ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}